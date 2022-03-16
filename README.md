FastAPI authentication with Microsoft Identity
==========================


The Microsoft Identity library for Python's FastAPI provides [Azure Active Directory](https://docs.microsoft.com/azure/active-directory/fundamentals/active-directory-whatis) token authentication and authorization through a set of convenience functions. It enables any FastAPI applications to authenticate with Azure AD to validate JWT tokens and API permissions 

Install the package
-------------
Install the Microsoft Identity for FastAPI library with [pip](https://pypi.org/project/fastapi-microsoft-identity/):
```
pip install fastapi-microsoft-identity
```

Prerequisites
-------------
- An Azure Active Directory [Get one FREE](https://aka.ms/425Show/devenv)
- Or an Azure Active Directory B2C, through a FREE Azure subscription [Get your Free sub](https://azure.microsoft.com/free)
- Python 3.6 or later

Usage
-------------

## 1. Azure AD Authentication
The library can now support both Azure AD and Azure AD B2C authentication for FastAPI applications

### 1.1 Azure AD App Registration Configuration
First create an Azure Active Directory `Application Registration` in the Azure AD portal using the following steps:
1. Sign in to your Azure AD Tenant ([link](aad.portal.azure.com)) 
2. Navigate to `App Registrations` -> `New Registration`.
3. Enter a name for your application.
4. Leave everything else as default.
5. Click `Register`.
6. Copy the `Client ID` and `Tenant ID` from the `Application Registration` **Overview** page.
7. Navigate to the `Expose API` tab.
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
In your FastAPI application, you need to initialize the authentication library using the `Client ID` and `Tenant ID` values from the `Application Registration` **Overview** page.

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

## 2. Azure AD B2C Authentication

### 2.1 Create your Azure AD B2C Application Registration

First create an Azure AD B2C `App Registration` in the B2C portal using the following steps:
1. Sign in to your Azure portal, search for your B2C tenant and navigate to the B2C portal
2. Navigate to `App Registrations` -> `New registration`.
3. Enter a name for your application.
4. Under `Supported account types` choose **Accounts in any identity provider or organizational directory(for authenticating user with user flows)**.
5. Make sure the **Grant admin consent to openid and offline_access** is checked. under `Permissions`
6. Click `Register`.
7. Copy the `Client ID` and `Tenant ID` from the `App Registration` **Overview** page.
8. Navigate to the `Expose API` tab.
9. Click `Set` next to the **Application ID URI** field.
10. Click **Add a scope**
    - Give the scope a name like `access_as_user`.
    - Provide meaningful descriptions for the admin consent name and description
    - Ensure `State` is set to **Enabled**
    - Client **Add scope**
11. From the B2C overview pane, copy the domaain name like this `<your-tenant>` ignoring the `.onmicrosoft.com.`. eg. cmatb2cdev

### 2.2 Using the Microsoft Identity for FastAPI library with Azure AD B2C

In your FastAPI application, you need to initialize the authentication library using the following values:
- `Client ID` 
- `Tenant ID` 
- `Domain Name`
- `Sign up & Sign In User Flow`

You need to make sure that both your Fast API and the API clients use the same B2C User flow to authenticate and acquire tokens.

You can read more about Azure AD User Flows and Policies [here](https://docs.microsoft.com/en-us/azure/active-directory-b2c/user-flow-overview)

```
initialize(tenant_id, client_id, b2c_policy_name, b2c_domain_name)
```
You can now decorate any API endpoint with the `requires_auth` decorator as per the example below

```
from fastapi_microsoft_identity import requires_auth, validate_scope, AuthError

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


Compatibility
-------------
Requires Python 3.x

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
