import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import crud, models, schemas
from app.db import Base
from unittest.mock import MagicMock
from sqlalchemy import engine
from sqlalchemy.orm import Session, sessionmaker

@pytest.fixture
def db():
    SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"  
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)  

    db_session = SessionLocal()
    yield db_session  
    db_session.close() 

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def mock_db():
    mock_db = MagicMock(Session)
    return mock_db

@pytest.fixture
def mock_user(mock_db):
    user_data = schemas.UserCreate(email="user@example.com", password="password")
    mock_user = models.User(email=user_data.email, password="hashed_password")
    mock_db.query().filter().first.return_value = mock_user
    return mock_user

def test_register_user(db, client):
    user_data = {"email": "newuser@example.com", "password": "password"}
    
    response = client.post("/register", json=user_data)
    assert response.status_code == 201
    assert response.json()["email"] == user_data["email"]

def test_login_user(client):
    login_data = {"email": "user@example.com", "password": "password"}
    response = client.post("/login", json=login_data)
    
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_create_contact(db, client):
    contact_data = {"name": "John Doe", "email": "john@example.com", "phone": "123456789"}
    
    mock_db.query().filter().first.return_value = mock_user
    
    response = client.post("/contacts/", json=contact_data, headers={"Authorization": "Bearer test_token"})
    
    assert response.status_code == 201
    assert response.json()["name"] == contact_data["name"]

def test_get_contacts(mock_db, client):
    contact_data = [{"name": "John Doe", "email": "john@example.com", "phone": "123456789"}]
    mock_db.query().filter().all.return_value = contact_data
    
    response = client.get("/contacts/", headers={"Authorization": "Bearer test_token"})
    
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["name"] == "John Doe"
