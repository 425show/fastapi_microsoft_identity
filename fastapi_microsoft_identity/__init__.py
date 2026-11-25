"""fastapi_microsoft_identity - Azure AD authentication for Fast API"""

__version__ = "0.2.0"
__author__ = "Christos Matskas <christos.matskas@microsoft.com>"

from .auth_service import (
    AuthError,
    get_token_auth_header,
    get_token_claims,
    initialize,
    requires_auth,
    requires_b2c_auth,
    validate_scope,
)

__all__ = [
    "AuthError",
    "get_token_auth_header",
    "get_token_claims",
    "initialize",
    "requires_auth",
    "requires_b2c_auth",
    "validate_scope",
]
