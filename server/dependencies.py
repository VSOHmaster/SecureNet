from typing import Generator, Optional, Union

from fastapi import Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session

from .database import SessionLocal
from . import models
from .auth import get_user_id_from_cookie

UserOrNone = Union[models.User, None]

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> models.User:
    user_id = get_user_id_from_cookie(request)
    login_url = request.url_for('login_page')

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": str(login_url)},
            detail="Not authenticated",
        )

    user = models.User.get_by_id(db, user_id)
    if user is None:
        raise HTTPException(
             status_code=status.HTTP_307_TEMPORARY_REDIRECT,
             headers={"Location": str(login_url)},
             detail="User not found",
        )

    return user

async def get_current_user_or_none(
    request: Request,
    db: Session = Depends(get_db)
) -> UserOrNone:
    user_id = get_user_id_from_cookie(request)
    if user_id is None:
        return None
    user = models.User.get_by_id(db, user_id)
    return user

async def require_admin(
    current_user: models.User = Depends(get_current_user)
) -> models.User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return current_user
