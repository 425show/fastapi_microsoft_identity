FastAPI authentication with Microsoft Identity
==========================


The Microsoft Identity library for Python's FastAPI provides [Microsoft Entra ID](https://learn.microsoft.com/entra/fundamentals/whatis) (formerly Azure Active Directory), [Microsoft Entra External ID](https://learn.microsoft.com/entra/external-id/customers/overview-customers-ciam) and Azure AD B2C token authentication and authorization through a set of convenience functions. It lets FastAPI applications validate JWT access tokens and API permissions issued by any of them.

Install the package
-------------
Install the Microsoft Identity for FastAPI library with [pip](https://pypi.org/project/fastapi-microsoft-identity/):
```
pip install fastapi-microsoft-identity
```

Prerequisites
-------------
- A Microsoft Entra ID tenant. A free one comes with the [Microsoft 365 Developer Program](https://developer.microsoft.com/microsoft-365/dev-program) or a [free Azure account](https://azure.microsoft.com/free)
- Or a Microsoft Entra External ID tenant, for customer-facing apps (see [section 3](#3-microsoft-entra-external-id-authentication))
- Or an existing Azure AD B2C tenant (see the [note in section 2](#2-azure-ad-b2c-authentication))
- Python 3.11 or later

Usage
-------------

## 1. Microsoft Entra ID Authentication
The library supports Microsoft Entra ID, Microsoft Entra External ID and Azure AD B2C authentication for FastAPI applications. Azure Active Directory (Azure AD) was renamed to Microsoft Entra ID in 2023. Only the name changed: the endpoints (`login.microsoftonline.com`), tokens and app registrations are the same, so nothing in your configuration needs to change.

### 1.1 Microsoft Entra ID App Registration Configuration
First create an `App registration` in the Microsoft Entra admin center using the following steps:
1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com).
2. Navigate to **Entra ID** -> `App registrations` -> `New registration`.
3. Enter a name for your application.
4. Leave everything else as default.
5. Click `Register`.
6. Copy the `Application (client) ID` and `Directory (tenant) ID` from the app registration's **Overview** page.
7. Navigate to the `Expose an API` tab.
8. Click `Set` next to the **Application ID URI** field.
9. Click **Add a scope**
    - Give the scope a name like `access_as_user`.
    - Select `Admin and User` for consent
    - Provide meaningful descriptions for the admin and user consents
    - Ensure `State` is set to **Enabled**
    - Client **Add scope**

The scope should look like this:
`api://279cfdb1-0000-0000-0000-291dcd4b561a/access_as_user`

### 1.2 Using the Microsoft Identity for FastAPI library
In your FastAPI application, you need to initialize the authentication library using the `Application (client) ID` and `Directory (tenant) ID` values from the app registration's **Overview** page.

```
initialize(tenant_id, client_id)
```
You can now decorate any API endpoint with the `requires_auth` decorator as per the example below

```
from fastapi_microsoft_identity import requires_auth, validate_scope, AuthError

expected_scope = "<your expected scope e.g access_as_user>"

@router.get('/api/weather/{city}')
@requires_auth
async def weather(request: Request, loc: Location = Depends(), units: Optional[str] = 'metric'):
    try:
        validate_scope(expected_scope, request)
        return await openweather_service.get_report_async(loc.city, loc.state, loc.country, units)
    except AuthError as ae:
        return fastapi.Response(content=ae.error_msg, status_code=ae.status_code)
    except ValidationError as ve:
        return fastapi.Response(content=ve.error_msg, status_code=ve.status_code)
    except Exception as x:
        return fastapi.Response(content=str(x), status_code=500)
```
The `requires_auth` decorator will check if the JWT Access Token in the request is a valid token and then raise an `AuthError` (HTTP 401) if the token is invalid (expired, not right audience etc).

The library also provides a helper function: `validate_scope` that can be used to validate the scope of the JWT token.

```
validate_scope(expected_scope, request)
```
The `validate_scope` method will throw an `AuthError` (HTTP 403) if the token doesn't contain the right scope / api permission.

### 1.3 Accessing the token claims
Based on user feedback, the library now provides a helper function to access the token claims.

Inside an endpoint protected by `requires_auth` / `requires_b2c_auth`, the **verified** claims are available on the request:

```python
token_claims = request.state.token_claims
```

`get_token_claims(request)` is also available, but it returns the claims **without** verifying the token, so only use it on protected endpoints.

### 1.4 Validating one of several scopes

`validate_scope` accepts a single scope or a list. The check passes if the token has any of them, either as a delegated scope (`scp`) or as an app role (`roles`):

```python
validate_scope(["access_as_user", "app.weather.read"], request)
```

### 1.5 Multi-tenant applications

To accept tokens from any Microsoft Entra ID tenant, pass `multitenant=True`. Signing keys come from the `common` endpoint. The issuer is still validated against the token's own `tid` claim, so you can restrict access to specific tenants with `allowed_tenants`:

```python
initialize(tenant_id, client_id, multitenant=True, allowed_tenants=["<tenant-guid>", "<tenant-guid>"])
```

### 1.6 How validation works

- Tokens must be RS256-signed by a key from the tenant's JWKS endpoint, and must include valid `exp`, `aud` and `iss` claims. `nbf` is checked when it's present.
- The accepted audiences are `<client_id>` and `api://<client_id>`.
- Signing keys are cached for an hour by default (`initialize(..., jwks_cache_ttl=3600)`). A token with an unknown `kid` triggers a refresh, so key rollover is picked up, but at most once a minute.
- The protected endpoint must declare a `request: Request` parameter. Both `async def` and regular `def` endpoints work.
- Failures return `401` with a `WWW-Authenticate: Bearer` header, or `503` if the signing keys can't be retrieved.

## 2. Azure AD B2C Authentication

> **Note:** Azure AD B2C kept its name in the Entra rebrand. Since May 2025 Microsoft no longer sells it to new customers, but existing tenants remain supported. For new customer-facing apps Microsoft recommends Microsoft Entra External ID, which this library supports too: see [section 3](#3-microsoft-entra-external-id-authentication).

### 2.1 Create your Azure AD B2C Application Registration

First create an Azure AD B2C `App Registration` in the B2C portal using the following steps:
1. Sign in to your Azure portal, search for your B2C tenant and navigate to the B2C portal
2. Navigate to `App Registrations` -> `New registration`.
3. Enter a name for your application.
4. Under `Supported account types` choose **Accounts in any identity provider or organizational directory(for authenticating user with user flows)**.
5. Make sure the **Grant admin consent to openid and offline_access** is checked. under `Permissions`
6. Click `Register`.
7. Copy the `Application (client) ID` and `Directory (tenant) ID` from the app registration's **Overview** page.
8. Navigate to the `Expose an API` tab.
9. Click `Set` next to the **Application ID URI** field.
10. Click **Add a scope**
    - Give the scope a name like `access_as_user`.
    - Provide meaningful descriptions for the admin consent name and description
    - Ensure `State` is set to **Enabled**
    - Client **Add scope**
11. From the B2C overview pane, copy the domain name like this `<your-tenant>`, leaving out `.onmicrosoft.com`, e.g. `cmatb2cdev`

### 2.2 Using the Microsoft Identity for FastAPI library with Azure AD B2C

In your FastAPI application, you need to initialize the authentication library using the following values:
- `Application (client) ID`
- `Directory (tenant) ID`
- `Domain Name`
- `Sign up & Sign In User Flow`

The issuer and signing keys are read from the user flow's OpenID Connect metadata (`https://<domain>.b2clogin.com/<domain>.onmicrosoft.com/<policy>/v2.0/.well-known/openid-configuration`).

You need to make sure that both your Fast API and the API clients use the same B2C User flow to authenticate and acquire tokens.

You can read more about Azure AD B2C user flows and policies [here](https://learn.microsoft.com/azure/active-directory-b2c/user-flow-overview)

```
initialize(tenant_id, client_id, b2c_policy_name, b2c_domain_name)
```
You can now decorate any API endpoint with the `requires_b2c_auth` decorator as per the example below

```
from fastapi_microsoft_identity import requires_b2c_auth, validate_scope, AuthError

expected_scope = "<your expected scope e.g access_as_user>"

@router.get('/api/weather/{city}')
@requires_b2c_auth
async def weather(request: Request, loc: Location = Depends(), units: Optional[str] = 'metric'):
    try:
        validate_scope(expected_scope, request)
        return await openweather_service.get_report_async(loc.city, loc.state, loc.country, units)
    except AuthError as ae:
        return fastapi.Response(content=ae.error_msg, status_code=ae.status_code)
    except ValidationError as ve:
        return fastapi.Response(content=ve.error_msg, status_code=ve.status_code)
    except Exception as x:
        return fastapi.Response(content=str(x), status_code=500)
```
The `requires_auth` decorator will check if the JWT Access Token in the request is a valid token and then raise an `AuthError` (HTTP 401) if the token is invalid (expired, not right audience etc).

The library also provides a helper function: `validate_scope` that can be used to validate the scope of the JWT token.

```
validate_scope(expected_scope, request)
```
The `validate_scope` method takes 2 parameters:
- expected_scope: The scope that the token should have (this can also be an app permission).
- request: The FastAPI Request object.

The method works out wether the access token contain an app permission (role) or a scope and then validate the claim.
If neither is present, the method throws an `AuthError` (HTTP 403) for the following reasons:
1. no `roles` or `scp` claim was present in the token
2. the token doesn't contain the right scope / api permission


## 3. Microsoft Entra External ID Authentication

[Microsoft Entra External ID](https://learn.microsoft.com/entra/external-id/customers/overview-customers-ciam) is Microsoft's identity service for customer-facing apps and the successor to Azure AD B2C. Its tenants sign users in at `<subdomain>.ciamlogin.com`.

### 3.1 Register your API in the External ID tenant

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) and switch to your external tenant.
2. Navigate to **Entra ID** -> `App registrations` -> `New registration`, give the API a name, and click `Register`.
3. Copy the `Application (client) ID` and `Directory (tenant) ID` from the **Overview** page.
4. Navigate to `Expose an API`, set the **Application ID URI**, and add a scope such as `access_as_user`.
5. Note the tenant's subdomain: for `contoso.onmicrosoft.com` the sign-in host is `contoso.ciamlogin.com`, so the subdomain is `contoso`.
6. Make sure the API issues v2.0 access tokens: in the app registration's `Manifest`, set `requestedAccessTokenVersion` (shown as `accessTokenAcceptedVersion` in older manifests) to `2`.

### 3.2 Using the library with External ID

Pass the tenant ID, client ID and `external_id_domain` to `initialize`, then protect endpoints with `requires_external_id_auth`:

```python
import fastapi
from fastapi import Request
from fastapi_microsoft_identity import initialize, requires_external_id_auth, validate_scope, AuthError

initialize(tenant_id, client_id, external_id_domain="contoso")

@router.get("/api/orders")
@requires_external_id_auth
async def orders(request: Request):
    try:
        validate_scope("access_as_user", request)
    except AuthError as ae:
        return fastapi.Response(content=ae.error_msg, status_code=ae.status_code)
    customer_id = request.state.token_claims["sub"]
    ...
```

`external_id_domain` accepts the subdomain (`contoso`), the full host (`contoso.ciamlogin.com`), or a [custom URL domain](https://learn.microsoft.com/entra/external-id/customers/how-to-custom-url-domain) such as `login.contoso.com`.

The issuer and signing keys are read from the tenant's OpenID Connect metadata (`https://<host>/<tenant_id>/v2.0/.well-known/openid-configuration`). The token's audience must be `<client_id>` or `api://<client_id>`, and its `tid` claim must match your tenant. Tokens from regular Entra ID tenants are rejected, and External ID tokens are rejected by `requires_auth`.


Compatibility
-------------
Requires Python 3.11+. Version 0.2.0 replaced `python-jose` with `PyJWT`. The public API is unchanged. Version 0.2.1 added Microsoft Entra External ID support.

Development
-------------
```
pip install -e ".[dev]"
pytest
```
The tests sign tokens with a locally generated key, so they don't need network access or real Microsoft Entra ID tokens.

Licence
-------------
MIT

Provide feedback
-------------
If you encounter bugs or have suggestions, please open an issue.

Contributing
-------------
This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information, see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact opencode@microsoft.com with any additional questions or comments.

Authors
-------
The `fastapi_microsoft_identity` was written by `Christos Matskas <christos.matskas@microsoft.com>`.
