import base64
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Request
from fastapi.testclient import TestClient

from fastapi_microsoft_identity import auth_service

TENANT_ID = "66ba9476-0700-4178-81ea-fbeb7097c28e"
OTHER_TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
CLIENT_ID = "de2656e6-585f-4684-8e65-3ce50a7770a8"
KID = "test-key-1"
B2C_DOMAIN = "contosob2c"
B2C_POLICY = "B2C_1_signupsignin"


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(rsa_key):
    pub = rsa_key.public_key().public_numbers()
    # Real Azure JWKS entries carry extra fields; B2C keys have "nbf", AAD keys have "x5c".
    return {"keys": [{"kid": KID, "kty": "RSA", "use": "sig", "n": _b64(pub.n), "e": _b64(pub.e)}]}


@pytest.fixture
def fetch_log(monkeypatch, jwks):
    """Replace network access with canned Azure responses. Returns the list of fetched URLs."""
    calls = []
    b2c_jwks_uri = f"https://{B2C_DOMAIN}.b2clogin.com/{B2C_DOMAIN}.onmicrosoft.com/{B2C_POLICY.lower()}/discovery/v2.0/keys"
    responses = {
        f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys": jwks,
        "https://login.microsoftonline.com/common/discovery/v2.0/keys": jwks,
        f"https://{B2C_DOMAIN}.b2clogin.com/{B2C_DOMAIN}.onmicrosoft.com/{B2C_POLICY}/v2.0/.well-known/openid-configuration": {
            "issuer": f"https://{B2C_DOMAIN}.b2clogin.com/{TENANT_ID}/v2.0/",
            "jwks_uri": b2c_jwks_uri,
        },
        b2c_jwks_uri: jwks,
    }

    async def fake_fetch(url):
        calls.append(url)
        if url not in responses:
            raise auth_service.AuthError("Unable to retrieve signing keys from the identity provider", 503)
        return responses[url]

    monkeypatch.setattr(auth_service, "_fetch_json", fake_fetch)
    return calls


@pytest.fixture(autouse=True)
def configure():
    auth_service.initialize(TENANT_ID, CLIENT_ID)
    yield
    auth_service.initialize(TENANT_ID, CLIENT_ID)


@pytest.fixture
def make_token(rsa_key):
    def _make(key=None, kid=KID, alg="RS256", **overrides):
        now = int(time.time())
        claims = {
            "aud": CLIENT_ID,
            "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "tid": TENANT_ID,
            "ver": "2.0",
            "scp": "access_as_user",
            "oid": str(uuid.uuid4()),
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or rsa_key, algorithm=alg, headers={"kid": kid})

    return _make


def make_request(headers: dict) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope)


@pytest.fixture
def client():
    from fastapi import FastAPI

    from fastapi_microsoft_identity import AuthError, requires_auth, requires_b2c_auth, validate_scope

    app = FastAPI()

    @app.get("/aad")
    @requires_auth
    async def aad(request: Request):
        return {"oid": request.state.token_claims["oid"]}

    @app.get("/aad-scope")
    @requires_auth
    async def aad_scope(request: Request):
        try:
            validate_scope("access_as_user", request)
        except AuthError as e:
            return {"error": e.error_msg, "status": e.status_code}
        return {"ok": True}

    @app.get("/sync")
    @requires_auth
    def sync_endpoint(request: Request):
        return {"sync": True}

    @app.get("/b2c")
    @requires_b2c_auth
    async def b2c(request: Request):
        return {"ok": True}

    @app.get("/no-request")
    @requires_auth
    async def no_request():
        return {"ok": True}

    return TestClient(app)
