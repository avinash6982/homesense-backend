from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from schemas import UserCreate, UserLogin, UserResponse, TokenResponse, RefreshRequest
from models import User
from security import (
    hash_password,
    verify_password,
    create_access_token,
    issue_refresh_token,
    rotate_refresh_token,
    revoke_refresh_token,
    get_current_user,
)

app = FastAPI()


@app.post("/auth/signup", response_model=UserResponse)
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(email=user.email, hashed_password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post("/auth/signin", response_model=TokenResponse)
def signin(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not verify_password(user.password, existing_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    access_token = create_access_token({"sub": str(existing_user.id)})
    refresh_token = issue_refresh_token(db, existing_user.id)

    return {"access_token": access_token, "refresh_token": refresh_token}


@app.get("/auth/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user


@app.post("/auth/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    access_token, refresh_token = rotate_refresh_token(db, payload.refresh_token)
    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/auth/logout")
def logout(payload: RefreshRequest, db: Session = Depends(get_db)):
    revoke_refresh_token(db, payload.refresh_token)
    return {"detail": "Logged out"}
