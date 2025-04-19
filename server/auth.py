from datetime import timedelta, datetime
from typing import Optional

from fastapi import Request, Response, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

from . import models
from .config import config

SECRET_KEY = config.SECRET_KEY
if 'default-insecure' in SECRET_KEY:
    print("Warning: Using default SECRET_KEY. Set a strong SECRET_KEY in .env for production!")

serializer = URLSafeTimedSerializer(SECRET_KEY)

SESSION_COOKIE_NAME = "session"
REMEMBER_ME_EXPIRY_SECONDS = 30 * 24 * 60 * 60

def create_session_cookie(response: Response, user_id: int, remember: bool = False):
    data = {"user_id": user_id}
    signed_data = serializer.dumps(data)
    max_age = REMEMBER_ME_EXPIRY_SECONDS if remember else None
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=signed_data,
        max_age=max_age,
        httponly=True,
        secure=False, # TODO: Set to True if using HTTPS
        samesite="lax"
    )

def get_user_id_from_cookie(request: Request) -> Optional[int]:
    signed_data = request.cookies.get(SESSION_COOKIE_NAME)
    if not signed_data:
        return None
    try:
        data = serializer.loads(signed_data, max_age=REMEMBER_ME_EXPIRY_SECONDS + 60)
        return data.get("user_id")
    except SignatureExpired:
        return None
    except BadSignature:
        return None
    except Exception as e:
        print(f"Error decoding session cookie: {e}")
        return None

def delete_session_cookie(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=False, # Match settings used in set_cookie
        samesite="lax"
    )

def set_flash_message(response: Response, message: str, category: str = "info"):
    flashes = []
    flashes.append({"message": message, "category": category})
    signed_flashes = serializer.dumps(flashes)

    response.set_cookie(
        key=SESSION_COOKIE_NAME + "_flash",
        value=signed_flashes,
        max_age=10,
        httponly=True,
        secure=False, # TODO: Use True with HTTPS
        samesite="lax",
        path="/"
    )

def get_flashed_messages(request: Request, response: Response) -> list:
    signed_flashes = request.cookies.get(SESSION_COOKIE_NAME + "_flash")
    if not signed_flashes:
        return []

    try:
        flashes = serializer.loads(signed_flashes, max_age=15)
        response.set_cookie(
            key=SESSION_COOKIE_NAME + "_flash",
            value="",
            max_age=0,
            expires=0,
            httponly=True,
            secure=False,
            samesite="lax",
            path="/"
        )
        return flashes if isinstance(flashes, list) else []
    except (SignatureExpired, BadSignature):
        response.set_cookie(
            key=SESSION_COOKIE_NAME + "_flash", value="", max_age=0, expires=0,
             httponly=True, secure=False, samesite="lax", path="/"
             )
        return []
    except Exception as e:
         print(f"Error reading flash cookie: {e}")
         return []
