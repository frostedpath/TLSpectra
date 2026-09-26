from fastapi import Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.config import settings
from app.core.errors import SMSException

security_scheme = HTTPBearer(auto_error=False)

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security_scheme)) -> str:
    """
    Validates static bearer token.
    """
    if not credentials:
        raise SMSException(
            status_code=401,
            code="UNAUTHORIZED",
            message="Missing Authorization bearer token"
        )
    if credentials.credentials != settings.STATIC_BEARER_TOKEN:
        raise SMSException(
            status_code=401,
            code="UNAUTHORIZED",
            message="Invalid bearer token credentials"
        )
    return credentials.credentials
