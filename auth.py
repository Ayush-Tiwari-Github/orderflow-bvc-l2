# OrderFlow: Authentication module
# Handles token creation, verification, and the login endpoint.

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Configuration (do not modify)

SECRET_KEY = "orderflow-secret-key-do-not-use-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

router = APIRouter(prefix="/auth", tags=["auth"])

# Simulated user store — passwords are bcrypt hash of "secret"
USERS_DB = {
    "alice@orderflow.com": {
        "email": "alice@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "admin",
    },
    "bob@orderflow.com": {
        "email": "bob@orderflow.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "role": "viewer",
    },
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Pydantic models (do not modify)

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None


class User(BaseModel):
    email: str
    role: str


# Helper utilities (do not modify)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_user(email: str) -> Optional[dict]:
    """Return the user dict from USERS_DB or None if not found."""
    return USERS_DB.get(email)


# TODO 1: Generate a signed access token for an authenticated user.
# Accept the user data to embed and an optional expiry window.
# Fall back to the default expiry (30 minutes) if none is provided.

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# TODO 2: Verify an incoming token and extract the user identity from it.
# Reject anything that is expired, tampered with, or missing the user email.
# Return the email and role so the rest of the app knows who is making the request.
def decode_access_token(token:str) -> TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user identity",
                headers = {"WWW-Authenticate": "Bearer"},
            )
        return TokenData(email= email, role = role)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not valid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )



# TODO 3: A reusable auth check that any route can use to protect itself.
# Reads the token from the incoming request, verifies it, and returns the logged-in user.
# Reject the request if the token is invalid or the user no longer exists in the system.

async def get_current_user(token:str = Depends(oauth2_scheme)) -> User:
    token_data = decode_access_token(token)
    user = get_user(token_data.email)
    if user is None:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "User no longer exists",
            headers = {"WWW-Authenticate": "Bearer"},
        )
    return User(email=user["email"], role=user["role"])



# TODO 4: Login endpoint — accepts email and password, issues a signed token on success.
# Check the credentials against the user store and reject invalid combinations.
# On success, return a token the client can use for all subsequent requests

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["email"], "role": user["role"]})
    return Token(access_token = access_token, token_type="bearer")