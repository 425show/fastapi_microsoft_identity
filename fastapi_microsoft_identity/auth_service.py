"""Microsoft Entra ID / Azure AD B2C bearer token validation for FastAPI."""

from __future__ import annotations

import inspect
import re
import time
from collections.abc import Iterable
from functools import wraps
from typing import Any

import httpx
import jwt
from fastapi import Request, Response
from starlette.concurrency import run_in_threadpool

AAD_AUTHORITY = "https://login.microsoftonline.com"
ALGORITHMS = ["RS256"]
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

tenant_id: str | None = None
client_id: str | None = None
b2c_policy_name: str | None = None
b2c_domain_name: str | None = None
multitenant: bool = False
allowed_tenants: set[str] | None = None
jwks_cache_ttl: int = 3600

# Minimum seconds between forced JWKS refreshes triggered by an unknown "kid".
_JWKS_REFRESH_COOLDOWN = 60
# url -> {"fetched_at": float, "keys": {kid: jwk_dict}}
_jwks_cache: dict[str, dict[str, Any]] = {}
# url -> {"fetched_at": float, "data": dict}
_metadata_cache: dict[str, dict[str, Any]] = {}


def initialize(
    tenant_id_: str,
    client_id_: str,
    b2c_policy_name_: str | None = None,
    b2c_domain_name_: str | None = None,
    *,
    multitenant: bool = False,
    allowed_tenants: Iterable[str] | None = None,
    jwks_cache_ttl: int = 3600,
) -> None:
    """Configure the library.

    :param tenant_id_: Microsoft Entra ID tenant ID (ignored for signing keys when ``multitenant`` is set).
    :param client_id_: The API's application (client) ID; tokens must be issued for this audience.
    :param b2c_policy_name_: B2C user flow / policy name (B2C only).
    :param b2c_domain_name_: B2C tenant name without ``.onmicrosoft.com`` (B2C only).
    :param multitenant: Accept tokens issued by any Microsoft Entra ID tenant. The issuer is still
        validated against the token's own ``tid`` claim.
    :param allowed_tenants: Optional allow-list of tenant IDs when ``multitenant`` is set.
    :param jwks_cache_ttl: Seconds to cache signing keys and B2C metadata.
    """
    global tenant_id, client_id, b2c_policy_name, b2c_domain_name
    tenant_id = tenant_id_
    client_id = client_id_
    b2c_policy_name = b2c_policy_name_
    b2c_domain_name = b2c_domain_name_
    globals()["multitenant"] = bool(multitenant)
    globals()["allowed_tenants"] = {t.lower() for t in allowed_tenants} if allowed_tenants else None
    globals()["jwks_cache_ttl"] = int(jwks_cache_ttl)
    clear_cache()


def clear_cache() -> None:
    """Drop cached signing keys and metadata."""
    _jwks_cache.clear()
    _metadata_cache.clear()


class AuthError(Exception):
    def __init__(self, error_msg: str, status_code: int):
        super().__init__(error_msg)
        self.error_msg = error_msg
        self.status_code = status_code


# --------------------------------------------------------------------------- helpers

def get_token_auth_header(request: Request) -> str:
    auth = request.headers.get("Authorization")
    if not auth:
        raise AuthError("Authentication error: Authorization header is missing", 401)

    parts = auth.split()
    if not parts or parts[0].lower() != "bearer":
        raise AuthError("Authentication error: Authorization header must start with 'Bearer'", 401)
    if len(parts) == 1:
        raise AuthError("Authentication error: Token not found", 401)
    if len(parts) > 2:
        raise AuthError("Authentication error: Authorization header must be 'Bearer <token>'", 401)
    return parts[1]


def _unverified_claims(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        raise AuthError("Token error: Unable to parse authentication", 401)


def get_token_claims(request: Request) -> dict[str, Any]:
    """Return the bearer token's claims.

    The claims are NOT verified by this function. Use it on endpoints protected by
    ``requires_auth`` / ``requires_b2c_auth`` (verified claims are also available as
    ``request.state.token_claims`` there).
    """
    return _unverified_claims(get_token_auth_header(request))


def validate_scope(required_scope: str | Iterable[str], request: Request) -> None:
    """Ensure the token holds at least one of the required scopes (``scp``) or app roles (``roles``).

    Raises ``AuthError`` (403) otherwise. Comparison is case-insensitive.
    """
    if isinstance(required_scope, str):
        required = {required_scope.lower()}
    else:
        required = {s.lower() for s in required_scope}
    if not required:
        raise ValueError("required_scope must not be empty")

    claims = _unverified_claims(get_token_auth_header(request))
    scp = claims.get("scp")
    roles = claims.get("roles")
    if not scp and not roles:
        raise AuthError("IDW10201: No scope or app permission (role) claim was found in the bearer token", 403)

    token_scopes = {s.lower() for s in scp.split()} if isinstance(scp, str) else set()
    token_roles = {r.lower() for r in roles if isinstance(r, str)} if isinstance(roles, list) else set()

    if required & (token_scopes | token_roles):
        return

    wanted = ", ".join(sorted(required))
    if token_roles and not token_scopes:
        raise AuthError(f'IDW10203: The "role" claim does not contain role {wanted} or was not found', 403)
    raise AuthError(f'IDW10203: The "scope" or "scp" claim does not contain scopes {wanted} or was not found', 403)


async def _fetch_json(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, ValueError):
        raise AuthError("Unable to retrieve signing keys from the identity provider", 503)


async def _get_metadata(url: str) -> dict[str, Any]:
    cached = _metadata_cache.get(url)
    if cached and time.monotonic() - cached["fetched_at"] < jwks_cache_ttl:
        return cached["data"]
    data = await _fetch_json(url)
    _metadata_cache[url] = {"fetched_at": time.monotonic(), "data": data}
    return data


async def _get_signing_key(jwks_url: str, kid: str) -> Any:
    now = time.monotonic()
    cached = _jwks_cache.get(jwks_url)
    fresh = cached is not None and now - cached["fetched_at"] < jwks_cache_ttl
    # Refresh when stale, or on an unknown kid (key rollover), with a cooldown so
    # tokens with bogus kids can't make us hammer the endpoint.
    if not fresh or (kid not in cached["keys"] and now - cached["fetched_at"] >= _JWKS_REFRESH_COOLDOWN):
        jwks = await _fetch_json(jwks_url)
        keys = {k["kid"]: k for k in jwks.get("keys", []) if isinstance(k, dict) and "kid" in k}
        cached = {"fetched_at": now, "keys": keys}
        _jwks_cache[jwks_url] = cached
    jwk = cached["keys"].get(kid)
    if jwk is None:
        raise AuthError("Invalid header error: Unable to find appropriate key", 401)
    try:
        return jwt.PyJWK(jwk, algorithm="RS256").key
    except jwt.PyJWTError:
        raise AuthError("Invalid header error: Unable to find appropriate key", 401)


def _decode(token: str, key: Any, audience: list[str] | str, issuer: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthError("Token error: The token has expired", 401)
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError):
        raise AuthError("Token error: Please check the audience and issuer", 401)
    except jwt.PyJWTError:
        raise AuthError("Token error: Unable to parse authentication", 401)


def _unverified_kid(token: str) -> str:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise AuthError("Invalid_header: Unable to parse authentication", 401)
    if header.get("alg") not in ALGORITHMS or not header.get("kid"):
        raise AuthError("Invalid_header: Unable to parse authentication", 401)
    return header["kid"]


def _require_configured(*values: Any) -> None:
    if any(v is None for v in values):
        raise AuthError("Authentication is not configured: call initialize() first", 500)


async def _verify_aad_token(token: str) -> dict[str, Any]:
    _require_configured(client_id, *(() if multitenant else (tenant_id,)))
    kid = _unverified_kid(token)
    claims = _unverified_claims(token)

    version = claims.get("ver")
    if version not in ("1.0", "2.0"):
        raise AuthError("Missing version claim from token. Unable to validate", 401)

    if multitenant:
        token_tenant = claims.get("tid")
        if not isinstance(token_tenant, str) or not _GUID_RE.match(token_tenant):
            raise AuthError("Token error: Please check the audience and issuer", 401)
        if allowed_tenants is not None and token_tenant.lower() not in allowed_tenants:
            raise AuthError("Token error: Tenant is not allowed", 401)
        issuer_tenant = token_tenant
        keys_tenant = "common"
    else:
        issuer_tenant = keys_tenant = tenant_id

    if version == "1.0":
        issuer = f"https://sts.windows.net/{issuer_tenant}/"
    else:
        issuer = f"{AAD_AUTHORITY}/{issuer_tenant}/v2.0"

    key = await _get_signing_key(f"{AAD_AUTHORITY}/{keys_tenant}/discovery/v2.0/keys", kid)
    return _decode(token, key, [client_id, f"api://{client_id}"], issuer)


async def _verify_b2c_token(token: str) -> dict[str, Any]:
    _require_configured(client_id, b2c_domain_name, b2c_policy_name)
    kid = _unverified_kid(token)
    metadata_url = (
        f"https://{b2c_domain_name}.b2clogin.com/{b2c_domain_name}.onmicrosoft.com/"
        f"{b2c_policy_name}/v2.0/.well-known/openid-configuration"
    )
    metadata = await _get_metadata(metadata_url)
    issuer = metadata.get("issuer")
    jwks_uri = metadata.get("jwks_uri")
    if not issuer or not jwks_uri:
        raise AuthError("Unable to retrieve signing keys from the identity provider", 503)
    key = await _get_signing_key(jwks_uri, kid)
    return _decode(token, key, client_id, issuer)


def _find_request(args: tuple, kwargs: dict) -> Request | None:
    for value in (*kwargs.values(), *args):
        if isinstance(value, Request):
            return value
    return None


def _error_response(err: AuthError) -> Response:
    headers = {}
    if err.status_code == 401:
        headers["WWW-Authenticate"] = 'Bearer error="invalid_token"'
    return Response(content=err.error_msg, status_code=err.status_code, media_type="text/plain", headers=headers)


def _make_decorator(verify):
    def decorator(f):
        is_async = inspect.iscoroutinefunction(f)

        @wraps(f)
        async def decorated(*args, **kwargs):
            request = _find_request(args, kwargs)
            if request is None:
                return _error_response(AuthError(
                    "Authentication is misconfigured: the endpoint must declare a 'request: Request' parameter",
                    500,
                ))
            try:
                token = get_token_auth_header(request)
                request.state.token_claims = await verify(token)
            except AuthError as auth_err:
                return _error_response(auth_err)
            if is_async:
                return await f(*args, **kwargs)
            return await run_in_threadpool(f, *args, **kwargs)

        return decorated

    return decorator


requires_auth = _make_decorator(_verify_aad_token)
requires_auth.__doc__ = "Require a valid Microsoft Entra ID bearer token. The endpoint must take a ``Request`` parameter."

requires_b2c_auth = _make_decorator(_verify_b2c_token)
requires_b2c_auth.__doc__ = "Require a valid Azure AD B2C bearer token. The endpoint must take a ``Request`` parameter."
