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
- An Azure Active Directory [Get one Free](https://aka.ms/425Show/devenv)
- Python 3.6 or later

Usage
-------------

## 1. Azure AD App Registration Configuration
First create an Azure Active Directory `Application Registration` in the Azure AD portal using the following steps:
1. Sign in to your Azure AD Tenant ([link](aad.portal.azure.com)) 
2. Navigate to `Applications` -> `Create a new application`.
3. Enter a name for your application.
4. Leave everything else as default.
5. Click `Create`.
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

## 2. Using the Microsoft Identity for FastAPI library
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
The `requires_auth` decorator will check the JWT Access Token a valid token the  and raise an `AuthError` (HTTP 401) if the token is invalid (expired, not right audience etc).

The library also provides a `validate_scope` function that can be used to validate the scope of the JWT token.

```
validate_scope(expected_scope, request)
```
`validate_scope` will raise an `AuthError` (HTTP 403) if the token is doesn't have the right scope / api permission).

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
