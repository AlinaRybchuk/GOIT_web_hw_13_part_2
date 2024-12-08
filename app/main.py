
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
from app import crud, models, schemas, db, auth 
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
    """
    Генерує унікальний токен для підтвердження електронної пошти користувача.
    
    :return: Токен у вигляді рядка.
    """
    return str(uuid.uuid4())

def send_verification_email(email: str, token: str, background_tasks: BackgroundTasks):
    """
    Додає задачу на відправку email для підтвердження реєстрації користувача.

    :param email: Електронна пошта користувача.
    :param token: Токен для підтвердження.
    :param background_tasks: Фонові задачі для відправки email.
    """
    background_tasks.add_task(_send_verification_email, email, token)

def _send_verification_email(email: str, token: str):
    """
    Реалізує відправку email з підтвердженням користувачеві.
    
    :param email: Електронна пошта користувача.
    :param token: Токен для підтвердження.
    """
    verification_url = f"http://localhost:8000/verify/{token}"
    message = f"Click here to verify your email: {verification_url}"

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):
    """
    Створює JWT токен доступу.

    :param data: Дані, які будуть закодовані в токен (наприклад, email користувача).
    :param expires_delta: Часова тривалість дії токену (за замовчуванням 15 хвилин).
    :return: Закодований JWT токен.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: timedelta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)):
    """
    Створює refresh токен для користувача.

    Ця функція генерує refresh токен на основі наданих даних, який може бути використаний 
    для отримання нового access токена після того, як поточний токен вийде з ладу. 
    Токен підписується за допомогою секретного ключа та алгоритму, заданого в конфігурації.

    :param data: Дані, які будуть закодовані в токен (зазвичай це ідентифікатор користувача або інші важливі дані).
    :param expires_delta: Час, протягом якого буде діяти refresh токен. За замовчуванням він триває `REFRESH_TOKEN_EXPIRE_DAYS` днів.
    :return: Закодований refresh токен у форматі JWT.
    
    :raises ValueError: Якщо виникає помилка при створенні токену (наприклад, через неправильний формат даних).
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta 
    to_encode.update({"exp": expire})  
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  
    return encoded_jwt

def verify_token(token: str):
    """
    Перевіряє достовірність JWT токену.
    
    :param token: Токен для перевірки.
    :return: Payload токену, якщо він дійсний, інакше None.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    """
    Отримує поточного користувача за допомогою токену.

    :param db: Сесія для роботи з базою даних.
    :param token: Токен користувача для автентифікації.
    :return: Користувач, якщо токен вірний.
    :raises HTTPException: Якщо токен недійсний або користувач не знайдений.
    """
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
    """
    Оновлює аватар користувача.

    :param file: Завантажений файл аватара.
    :param current_user: Поточний користувач, що оновлює аватар.
    :return: URL нового аватара.
    """
    result = cloudinary.uploader.upload(file.file)
    avatar_url = result["secure_url"]
    crud.update_user_avatar(current_user.id, avatar_url)
    return {"message": "Avatar updated successfully", "avatar_url": avatar_url}

redis_client = redis.Redis(
    host="localhost", 
    port=6379, 
    db=0, 
    decode_responses=True
)

@app.on_event("startup")
async def startup():
    await FastAPILimiter.init(app)

    
@app.post("/register", response_model=schemas.User, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """
    Реєструє нового користувача, зберігає його в базі даних та відправляє email для підтвердження.

    :param user: Дані нового користувача.
    :param background_tasks: Фонові задачі для відправки email.
    :param db: Сесія бази даних.
    :return: Інформація про нового користувача.
    :raises HTTPException: Якщо користувач уже існує.
    """
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
    """
    Підтверджує email користувача за допомогою токену.

    :param token: Токен підтвердження.
    :param db: Сесія бази даних.
    :return: Повідомлення про успішне підтвердження.
    :raises HTTPException: Якщо токен недійсний.
    """
    user = crud.verify_user_token(db, token)
    if not user:
        raise

@app.post("/login")
def login_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    Логін користувача за допомогою електронної пошти та пароля.

    Ця функція перевіряє надані облікові дані користувача (електронна пошта і пароль),
    і якщо вони правильні, створює та повертає JWT токен доступу.

    :param user: Дані користувача для авторизації (електронна пошта та пароль).
    :param db: Сесія бази даних для доступу до користувачів.
    :return: Токен доступу у форматі JWT та тип токену (bearer).
    :raises HTTPException: Якщо електронна пошта або пароль не співпадають з даними в базі.
    """
    db_user = crud.get_user_by_email(db, email=user.email)
    if not db_user or not crud.verify_password(user.password, db_user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/contacts/", response_model=schemas.Contact, status_code=status.HTTP_201_CREATED)
async def create_contact(contact: schemas.ContactCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    """
    Створює новий контакт для поточного користувача.

    Ця функція дозволяє користувачеві створювати новий контакт у своїй адресній книзі.
    Контакт додається до бази даних та прив'язується до користувача.

    :param contact: Дані нового контакту (ім'я, телефон, email тощо).
    :param db: Сесія для роботи з базою даних.
    :param current_user: Поточний користувач, який додає контакт.
    :return: Створений контакт, включаючи ID та інші деталі.
    """
    return crud.create_contact(db=db, contact=contact, user_id=current_user.id)

@app.get("/contacts/", response_model=List[schemas.Contact], dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def get_contacts(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    """
    Отримує список всіх контактів поточного користувача.

    Ця функція дозволяє користувачеві отримати список всіх своїх контактів,
    що зберігаються в базі даних. Запит обмежений лімітом на 5 запитів за 60 секунд.

    :param db: Сесія для роботи з базою даних.
    :param current_user: Поточний користувач, який запитує свої контакти.
    :return: Список контактів поточного користувача.
    :raises HTTPException: Якщо користувач не знайдений.
    """
    return crud.get_contacts(db=db, user_id=current_user.id)
