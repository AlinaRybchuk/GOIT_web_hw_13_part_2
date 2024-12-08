from sqlalchemy.orm import Session
from app import models, schemas, auth

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = auth.get_password_hash(user.password)  
    db_user = models.User(email=user.email, password=hashed_password)  
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_contact(db: Session, contact: schemas.ContactCreate, user_id: int):
    db_contact = models.Contact(**contact.model_dump(), owner_id=user_id)
  
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)
    return db_contact

def get_contacts(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return db.query(models.Contact).filter(models.Contact.user_id == user_id).offset(skip).limit(limit).all()

def get_contact_by_id(db: Session, contact_id: int, user_id: int):
    return db.query(models.Contact).filter(models.Contact.id == contact_id, models.Contact.user_id == user_id).first()

def update_contact(db: Session, contact_id: int, contact: schemas.ContactUpdate, user_id: int):
    db_contact = db.query(models.Contact).filter(models.Contact.id == contact_id, models.Contact.user_id == user_id).first()
    if db_contact:
        for key, value in contact.dict().items():
            setattr(db_contact, key, value)
        db.commit()
        db.refresh(db_contact)
    return db_contact

def delete_contact(db: Session, contact_id: int, user_id: int):
    db_contact = db.query(models.Contact).filter(models.Contact.id == contact_id, models.Contact.user_id == user_id).first()
    if db_contact:
        db.delete(db_contact)
        db.commit()
    return db_contact

def save_verification_token(db: Session, user_email: str, token: str):
    user = db.query(models.User).filter(models.User.email == user_email).first()
    user.verification_token = token
    db.commit()

def verify_user_token(db: Session, token: str):
    user = db.query(models.User).filter(models.User.verification_token == token).first()
    return user

def update_user_verification(db: Session, email: str):
    user = db.query(models.User).filter(models.User.email == email).first()
    user.is_verified = True
    user.verification_token = None 
    db.commit()

def update_user_avatar(db: Session, user_id: int, avatar_url: str):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    user.avatar_url = avatar_url
    db.commit()