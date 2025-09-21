"""
Authentication API endpoints for FastAPI
Handles login, registration, token refresh, and user management
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr, validator

from api.dependencies.database import get_db
from core.security import security_manager, rate_limiter, log_security_event
from models import User

logger = logging.getLogger(__name__)

router = APIRouter()

# OAuth2 scheme for FastAPI documentation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Pydantic models for request/response
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 30:
            raise ValueError('Username must be between 3 and 30 characters')
        if not v.isalnum():
            raise ValueError('Username must contain only alphanumeric characters')
        return v

    @validator('password')
    def validate_password(cls, v):
        validation = security_manager.validate_password_strength(v)
        if not validation["is_valid"]:
            raise ValueError(f"Password too weak: {', '.join(validation['feedback'])}")
        return v


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    is_active: bool
    is_staff: bool
    date_joined: datetime

    class Config:
        orm_mode = True


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenRefresh(BaseModel):
    refresh_token: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @validator('new_password')
    def validate_new_password(cls, v):
        validation = security_manager.validate_password_strength(v)
        if not validation["is_valid"]:
            raise ValueError(f"Password too weak: {', '.join(validation['feedback'])}")
        return v


class PasswordReset(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

    @validator('new_password')
    def validate_new_password(cls, v):
        validation = security_manager.validate_password_strength(v)
        if not validation["is_valid"]:
            raise ValueError(f"Password too weak: {', '.join(validation['feedback'])}")
        return v


# Helper functions
def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get user by username"""
    return db.query(User).filter(User.username == username).first()


def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get user by email"""
    return db.query(User).filter(User.email == email).first()


def create_user(db: Session, user_data: UserCreate) -> User:
    """Create new user"""
    # Check if user exists
    if get_user_by_username(db, user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    if get_user_by_email(db, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create user
    hashed_password = security_manager.get_password_hash(user_data.password)

    db_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hashed_password,
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        is_active=True,
        permissions=["scan_access", "report_access"],  # Default permissions
        roles=["user"]
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Authenticate user credentials"""
    user = get_user_by_username(db, username)
    if not user:
        return None

    if not security_manager.verify_password(password, user.password_hash):
        return None

    return user


def create_user_tokens(user: User) -> Dict[str, Any]:
    """Create access and refresh tokens for user"""
    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "permissions": user.permissions or [],
        "roles": user.roles or [],
        "is_active": user.is_active,
        "is_staff": user.is_staff,
        "is_superuser": user.is_superuser
    }

    access_token = security_manager.generate_access_token(user_data)
    refresh_token = security_manager.generate_refresh_token(user_data)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": security_manager.access_token_expire_minutes * 60,
        "user": user
    }


# API Endpoints
@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Register a new user"""
    client_ip = request.client.host

    # Rate limiting for registration
    if not rate_limiter.is_allowed(f"register_{client_ip}", 5, 3600):  # 5 per hour
        log_security_event("rate_limit_exceeded", {
            "endpoint": "register",
            "client_ip": client_ip
        })
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later."
        )

    try:
        # Create user
        user = create_user(db, user_data)

        # Generate tokens
        tokens = create_user_tokens(user)

        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()

        # Log successful registration
        log_security_event("user_registered", {
            "user_id": user.id,
            "username": user.username,
            "client_ip": client_ip
        })

        return tokens

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/token", response_model=TokenResponse)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """Login with username and password"""
    client_ip = request.client.host if request else "unknown"

    # Rate limiting for login attempts
    if not rate_limiter.is_allowed(f"login_{client_ip}", 10, 600):  # 10 per 10 minutes
        log_security_event("rate_limit_exceeded", {
            "endpoint": "login",
            "username": form_data.username,
            "client_ip": client_ip
        })
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )

    # Authenticate user
    user = authenticate_user(db, form_data.username, form_data.password)

    if not user:
        # Log failed login attempt
        log_security_event("login_failed", {
            "username": form_data.username,
            "client_ip": client_ip,
            "reason": "invalid_credentials"
        })

        # Update failed attempts
        user_record = get_user_by_username(db, form_data.username)
        if user_record:
            user_record.failed_login_attempts += 1
            if user_record.failed_login_attempts >= 5:
                # Lock account for 15 minutes
                user_record.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if account is locked
    if user.account_locked_until and user.account_locked_until > datetime.utcnow():
        log_security_event("login_failed", {
            "username": form_data.username,
            "client_ip": client_ip,
            "reason": "account_locked"
        })
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to too many failed attempts"
        )

    # Check if user is active
    if not user.is_active:
        log_security_event("login_failed", {
            "username": form_data.username,
            "client_ip": client_ip,
            "reason": "account_inactive"
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.account_locked_until = None
    user.last_login = datetime.utcnow()
    db.commit()

    # Generate tokens
    tokens = create_user_tokens(user)

    # Log successful login
    log_security_event("login_successful", {
        "user_id": user.id,
        "username": user.username,
        "client_ip": client_ip
    })

    return tokens


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    token_data: TokenRefresh,
    request: Request,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token"""
    client_ip = request.client.host

    try:
        # Verify refresh token
        payload = security_manager.verify_token(token_data.refresh_token)

        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )

        # Get user
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == int(user_id)).first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )

        # Generate new tokens
        tokens = create_user_tokens(user)

        # Log token refresh
        log_security_event("token_refreshed", {
            "user_id": user.id,
            "username": user.username,
            "client_ip": client_ip
        })

        return tokens

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(security_manager.verify_token)
):
    """Logout user (invalidate tokens - would need token blacklist in production)"""
    client_ip = request.client.host

    # In production, add token to blacklist
    # For now, just log the logout
    log_security_event("user_logout", {
        "user_id": current_user.get("sub"),
        "username": current_user.get("username"),
        "client_ip": client_ip
    })

    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(security_manager.verify_token),
    db: Session = Depends(get_db)
):
    """Get current user information"""
    user_id = current_user.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.put("/change-password")
async def change_password(
    password_data: PasswordChange,
    request: Request,
    current_user: dict = Depends(security_manager.verify_token),
    db: Session = Depends(get_db)
):
    """Change user password"""
    client_ip = request.client.host
    user_id = current_user.get("sub")

    # Get user
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Verify current password
    if not security_manager.verify_password(password_data.current_password, user.password_hash):
        log_security_event("password_change_failed", {
            "user_id": user.id,
            "username": user.username,
            "client_ip": client_ip,
            "reason": "invalid_current_password"
        })
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    # Update password
    user.password_hash = security_manager.get_password_hash(password_data.new_password)
    db.commit()

    # Log password change
    log_security_event("password_changed", {
        "user_id": user.id,
        "username": user.username,
        "client_ip": client_ip
    })

    return {"message": "Password changed successfully"}


@router.post("/reset-password")
async def request_password_reset(
    reset_data: PasswordReset,
    request: Request,
    db: Session = Depends(get_db)
):
    """Request password reset"""
    client_ip = request.client.host

    # Rate limiting
    if not rate_limiter.is_allowed(f"password_reset_{client_ip}", 3, 3600):  # 3 per hour
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset attempts"
        )

    user = get_user_by_email(db, reset_data.email)

    # Always return success to prevent email enumeration
    message = "If an account with that email exists, a password reset link has been sent."

    if user:
        # In production, send email with reset token
        # For now, just log the request
        log_security_event("password_reset_requested", {
            "user_id": user.id,
            "username": user.username,
            "email": user.email,
            "client_ip": client_ip
        })

    return {"message": message}


@router.get("/validate-token")
async def validate_token(current_user: dict = Depends(security_manager.verify_token)):
    """Validate if token is still valid"""
    return {
        "valid": True,
        "user_id": current_user.get("sub"),
        "username": current_user.get("username"),
        "exp": current_user.get("exp")
    }