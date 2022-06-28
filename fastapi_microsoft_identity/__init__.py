"""fastapi_microsoft_identity - Azure AD authentication for Fast API"""

from .auth_service import initialize, AuthError, validate_scope, requires_auth, requires_b2c_auth, get_token_claims

__version__ = '0.1.4'
__author__ = 'Christos Matskas <christos.matskas@microsoft.com>'
__all__ = (
    "initialize",
    "AuthError",
    "validate_scope",
    "requires_auth",
    "requires_b2c_auth",
    "get_token_claims",
)
