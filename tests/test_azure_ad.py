import time

import pytest

from fastapi_microsoft_identity import AuthError, auth_service, get_token_claims, validate_scope

from conftest import B2C_DOMAIN, B2C_POLICY, CLIENT_ID, OTHER_TENANT_ID, TENANT_ID, make_request


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ----------------------------------------------------------------- header parsing

def test_auth_header_has_token():
    assert auth_service.get_token_auth_header(make_request(bearer("abc"))) == "abc"


@pytest.mark.parametrize("value", [None, "", "Basic abc", "Bearer", "Bearer a b"])
def test_bad_auth_headers(value):
    headers = {} if value is None else {"Authorization": value}
    with pytest.raises(AuthError) as e:
        auth_service.get_token_auth_header(make_request(headers))
    assert e.value.status_code == 401


# ----------------------------------------------------------------- scopes / claims

def test_can_find_user_scope(make_token):
    validate_scope("ACCESS_AS_USER", make_request(bearer(make_token())))


def test_can_find_user_scope_but_is_wrong(make_token):
    with pytest.raises(AuthError) as e:
        validate_scope("access_as_user2", make_request(bearer(make_token())))
    assert "IDW10203" in e.value.error_msg
    assert e.value.status_code == 403


def test_can_find_application_role(make_token):
    token = make_token(scp=None, roles=["app.weather.read"])
    validate_scope("app.weather.read", make_request(bearer(token)))


def test_can_find_application_role_but_is_wrong(make_token):
    token = make_token(scp=None, roles=["app.weather.read"])
    with pytest.raises(AuthError) as e:
        validate_scope("access_as_user", make_request(bearer(token)))
    assert '"role"' in e.value.error_msg


def test_user_token_with_scope_and_roles(make_token):
    token = make_token(roles=["admin"])
    validate_scope("access_as_user", make_request(bearer(token)))
    validate_scope("admin", make_request(bearer(token)))


def test_scope_list_any_match(make_token):
    validate_scope(["other", "access_as_user"], make_request(bearer(make_token())))
    with pytest.raises(AuthError):
        validate_scope(["other", "another"], make_request(bearer(make_token())))


def test_no_scope_or_role(make_token):
    with pytest.raises(AuthError) as e:
        validate_scope("x", make_request(bearer(make_token(scp=None))))
    assert "IDW10201" in e.value.error_msg


def test_can_retrieve_token_claims(make_token):
    claims = get_token_claims(make_request(bearer(make_token(name="Abe"))))
    assert claims["name"] == "Abe"


def test_malformed_token_claims():
    with pytest.raises(AuthError):
        get_token_claims(make_request(bearer("not-a-jwt")))


# ----------------------------------------------------------------- requires_auth

def test_valid_token(client, make_token, fetch_log):
    token = make_token(oid="abc")
    r = client.get("/aad", headers=bearer(token))
    assert r.status_code == 200
    assert r.json() == {"oid": "abc"}


def test_v1_token_with_app_id_uri_audience(client, make_token, fetch_log):
    token = make_token(ver="1.0", iss=f"https://sts.windows.net/{TENANT_ID}/", aud=f"api://{CLIENT_ID}")
    assert client.get("/aad", headers=bearer(token)).status_code == 200


def test_sync_endpoint(client, make_token, fetch_log):
    r = client.get("/sync", headers=bearer(make_token()))
    assert r.json() == {"sync": True}


def test_validate_scope_inside_endpoint(client, make_token, fetch_log):
    assert client.get("/aad-scope", headers=bearer(make_token())).json() == {"ok": True}
    r = client.get("/aad-scope", headers=bearer(make_token(scp="other")))
    assert r.json()["status"] == 403


def test_missing_header(client, fetch_log):
    r = client.get("/aad")
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Bearer")
    assert fetch_log == []


def test_expired_token_reports_real_reason(client, make_token, fetch_log):
    now = int(time.time())
    r = client.get("/aad", headers=bearer(make_token(exp=now - 10, iat=now - 3600, nbf=now - 3600)))
    assert r.status_code == 401
    assert "expired" in r.text


def test_wrong_audience(client, make_token, fetch_log):
    r = client.get("/aad", headers=bearer(make_token(aud="someone-else")))
    assert r.status_code == 401
    assert "audience" in r.text


def test_wrong_issuer(client, make_token, fetch_log):
    r = client.get("/aad", headers=bearer(make_token(iss="https://evil.example/v2.0")))
    assert r.status_code == 401
    assert "issuer" in r.text


def test_token_from_other_tenant_rejected_single_tenant(client, make_token, fetch_log):
    token = make_token(tid=OTHER_TENANT_ID, iss=f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0")
    assert client.get("/aad", headers=bearer(token)).status_code == 401


def test_missing_exp_rejected(client, make_token, fetch_log):
    assert client.get("/aad", headers=bearer(make_token(exp=None))).status_code == 401


def test_bad_signature(client, make_token, other_rsa_key, fetch_log):
    r = client.get("/aad", headers=bearer(make_token(key=other_rsa_key)))
    assert r.status_code == 401


def test_unknown_kid(client, make_token, fetch_log):
    r = client.get("/aad", headers=bearer(make_token(kid="nope")))
    assert r.status_code == 401
    assert "appropriate key" in r.text


def test_hs256_token_rejected(client, make_token, fetch_log):
    token = make_token(key="a-shared-secret-that-is-long-enough-for-hs256", alg="HS256")
    assert client.get("/aad", headers=bearer(token)).status_code == 401


def test_missing_version_claim(client, make_token, fetch_log):
    assert client.get("/aad", headers=bearer(make_token(ver=None))).status_code == 401


def test_endpoint_without_request_param(client, make_token, fetch_log):
    r = client.get("/no-request", headers=bearer(make_token()))
    assert r.status_code == 500


def test_jwks_is_cached(client, make_token, fetch_log):
    for _ in range(3):
        assert client.get("/aad", headers=bearer(make_token())).status_code == 200
    assert len(fetch_log) == 1


def test_unknown_kid_refresh_is_rate_limited(client, make_token, fetch_log):
    assert client.get("/aad", headers=bearer(make_token())).status_code == 200
    for _ in range(3):
        client.get("/aad", headers=bearer(make_token(kid="rotated")))
    assert len(fetch_log) == 1


def test_jwks_unreachable(client, make_token, monkeypatch, fetch_log):
    auth_service.initialize("00000000-0000-0000-0000-000000000000", CLIENT_ID)
    token = make_token(iss="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0")
    assert client.get("/aad", headers=bearer(token)).status_code == 503


# ----------------------------------------------------------------- multi-tenant

def test_multitenant_accepts_other_tenant(client, make_token, fetch_log):
    auth_service.initialize(TENANT_ID, CLIENT_ID, multitenant=True)
    token = make_token(tid=OTHER_TENANT_ID, iss=f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0")
    assert client.get("/aad", headers=bearer(token)).status_code == 200
    assert fetch_log == ["https://login.microsoftonline.com/common/discovery/v2.0/keys"]


def test_multitenant_still_validates_issuer(client, make_token, fetch_log):
    auth_service.initialize(TENANT_ID, CLIENT_ID, multitenant=True)
    # issuer doesn't match the token's own tid
    token = make_token(tid=OTHER_TENANT_ID, iss=f"https://login.microsoftonline.com/{TENANT_ID}/v2.0")
    assert client.get("/aad", headers=bearer(token)).status_code == 401
    token = make_token(tid=OTHER_TENANT_ID, iss="https://evil.example/v2.0")
    assert client.get("/aad", headers=bearer(token)).status_code == 401


def test_multitenant_allow_list(client, make_token, fetch_log):
    auth_service.initialize(TENANT_ID, CLIENT_ID, multitenant=True, allowed_tenants=[TENANT_ID])
    other = make_token(tid=OTHER_TENANT_ID, iss=f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0")
    assert client.get("/aad", headers=bearer(other)).status_code == 401
    assert client.get("/aad", headers=bearer(make_token())).status_code == 200


def test_multitenant_requires_tid(client, make_token, fetch_log):
    auth_service.initialize(TENANT_ID, CLIENT_ID, multitenant=True)
    assert client.get("/aad", headers=bearer(make_token(tid=None))).status_code == 401


# ----------------------------------------------------------------- B2C

@pytest.fixture
def b2c_config():
    auth_service.initialize(TENANT_ID, CLIENT_ID, B2C_POLICY, B2C_DOMAIN)


def b2c_issuer():
    return f"https://{B2C_DOMAIN}.b2clogin.com/{TENANT_ID}/v2.0/"


def test_b2c_valid_token(client, make_token, fetch_log, b2c_config):
    token = make_token(iss=b2c_issuer(), ver="1.0", tid=None)
    assert client.get("/b2c", headers=bearer(token)).status_code == 200


def test_b2c_wrong_issuer(client, make_token, fetch_log, b2c_config):
    token = make_token(iss=f"https://{B2C_DOMAIN}.b2clogin.com/{TENANT_ID}/v2.0")  # missing trailing slash
    assert client.get("/b2c", headers=bearer(token)).status_code == 401


def test_b2c_wrong_audience(client, make_token, fetch_log, b2c_config):
    token = make_token(iss=b2c_issuer(), aud="other")
    assert client.get("/b2c", headers=bearer(token)).status_code == 401


def test_b2c_not_configured(client, make_token, fetch_log):
    assert client.get("/b2c", headers=bearer(make_token())).status_code == 500
