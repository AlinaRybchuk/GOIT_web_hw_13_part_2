
from fastapi import FastAPI, BackgroundTasks, UploadFile, File, Depends, HTTPException, status
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from typing import List
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta

import cloudinary
import cloudinary.uploader
import cloudinary.api
import redis.asyncio as redis
import uuid
import crud, models, schemas, db, auth 
import os

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")

REDIS_HOST = os.getenv("REDIS_HOST")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.sqlite"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"],  
)

models.Base.metadata.create_all(bind=db.engine)

def get_db():
    db = db.SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def generate_verification_token():
    return str(uuid.uuid4())

def send_verification_email(email: str, token: str, background_tasks: BackgroundTasks):
    background_tasks.add_task(_send_verification_email, email, token)

def _send_verification_email(email: str, token: str):
    verification_url = f"http://localhost:8000/verify/{token}"
    message = f"Click here to verify your email: {verification_url}"

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = crud.get_user_by_email(db, email=payload.get("sub"))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

def get_token(token: str = Depends(oauth2_scheme)):
    user = auth.verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

@app.post("/user/avatar")
async def update_avatar(file: UploadFile = File(...), current_user: models.User = Depends(get_current_user)):
    result = cloudinary.uploader.upload(file.file)
    avatar_url = result["secure_url"]
    crud.update_user_avatar(current_user.id, avatar_url)
    return {"message": "Avatar updated successfully", "avatar_url": avatar_url}


redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    db=int(os.getenv("REDIS_DB", 0)),
    decode_responses=True
)

@app.on_event("startup")
async def startup():
    await FastAPILimiter.init(redis_client)
    
@app.post("/register", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    try:
        new_user = crud.create_user(db, user)
        verification_token = generate_verification_token()
        crud.save_verification_token(db, user_email=user.email, token=verification_token)
        send_verification_email(user.email, verification_token, background_tasks)
        return new_user
    except ValueError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

@app.get("/verify/{token}", status_code=status.HTTP_200_OK)
def verify_email(token: str, db: Session = Depends(get_db)):
    user = crud.verify_user_token(db, token)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    crud.update_user_verification(db, user.email)
    return {"message": "Email verified successfully"}

@app.post("/login")
def login_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if not db_user or not crud.verify_password(user.password, db_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/contacts/", response_model=schemas.Contact, status_code=status.HTTP_201_CREATED)
async def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return crud.create_contact(db=db, contact=contact, user_id=current_user.id)

@app.get("/contacts/", response_model=List[schemas.Contact], dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def get_contacts(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return crud.get_contacts(db=db, user_id=current_user.id)

