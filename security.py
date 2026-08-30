import hashlib
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from config import JWT_SECRET_KEY
from database import get_db
from models import User, RefreshToken

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()

SECRET_KEY = JWT_SECRET_KEY
ALGORITHM = "HS256"
REFRESH_TOKEN_EXPIRE_DAYS = 7


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_minutes: int = 15) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise ValueError("Invalid or expired token")


def create_refresh_token(data: dict, expires_days: int = REFRESH_TOKEN_EXPIRE_DAYS) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=expires_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_refresh_token(db: Session, user_id: int) -> str:
    token = create_refresh_token({"sub": str(user_id)})
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    db_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(token),
        expires_at=expires_at,
        revoked=False,
    )
    db.add(db_token)
    db.commit()

    return token


def rotate_refresh_token(db: Session, token: str) -> tuple[str, str]:
    invalid_token_error = HTTPException(status_code=401, detail="Invalid or expired refresh token")

    try:
        payload = decode_token(token)
    except ValueError:
        raise invalid_token_error

    if payload.get("type") != "refresh":
        raise invalid_token_error

    user_id = payload.get("sub")
    if user_id is None:
        raise invalid_token_error

    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(token)).first()
    if db_token is None or db_token.revoked:
        raise invalid_token_error

    if db_token.expires_at < datetime.now(timezone.utc):
        raise invalid_token_error

    db_token.revoked = True
    db.commit()

    new_access_token = create_access_token({"sub": user_id})
    new_refresh_token = issue_refresh_token(db, int(user_id))

    return new_access_token, new_refresh_token


def revoke_refresh_token(db: Session, token: str) -> None:
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == hash_token(token)).first()
    if db_token is not None:
        db_token.revoked = True
        db.commit()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    credentials_error = HTTPException(status_code=401, detail="Could not validate credentials")

    try:
        payload = decode_token(credentials.credentials)
    except ValueError:
        raise credentials_error

    if payload.get("type") != "access":
        raise credentials_error

    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_error

    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_error

    return user
