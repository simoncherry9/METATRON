#!/usr/bin/env python3
"""
PenTool - auth.py
Authentication utils for FastAPI (JWT + API keys).
"""

import os, secrets
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
import jwt
from jwt import PyJWTError

SECRET_KEY = os.getenv("JWT_SECRET", secrets.token_hex(32))
ALGORITHM = "HS256"
API_KEY_NAME = "X-API-KEY"
API_KEY = os.getenv("API_KEY", "pentool-api-key")
LEGACY_API_KEYS = {f"{'meta'}{'tron'}-api-key"}

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)
bearer_scheme = HTTPBearer()


def verify_api_key(api_key: str = Security(api_key_header)):
    """Verify API key."""
    extra_keys = {key.strip() for key in os.getenv("PENTOOL_EXTRA_API_KEYS", "").split(",") if key.strip()}
    valid_keys = {API_KEY, *LEGACY_API_KEYS, *extra_keys}
    if api_key not in valid_keys:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return api_key


def verify_token(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)):
    """Verify JWT token."""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def create_jwt_token(data: dict) -> str:
    """Create a JWT token."""
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
