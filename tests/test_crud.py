import unittest
from unittest.mock import MagicMock
from sqlalchemy.orm import Session
from app import crud, models, schemas

class TestCRUD(unittest.TestCase):

    def setUp(self):
        self.mock_db = MagicMock(Session)

    def test_get_user_by_email(self):
        email = "test@example.com"
        mock_user = models.User(email=email, password="hashed_password")
        self.mock_db.query().filter().first.return_value = mock_user
        
        user = crud.get_user_by_email(self.mock_db, email)
        self.assertEqual(user.email, email)
        self.assertIsNotNone(user)
    
    def test_create_user(self):
        user_data = schemas.UserCreate(email="newuser@example.com", password="password")
        hashed_password = "hashed_password"

        new_user = models.User(email=user_data.email, password=user_data.password)
        
        self.mock_db.add.return_value = None
        self.mock_db.commit.return_value = None
        self.mock_db.refresh.return_value = new_user
        
        created_user = crud.create_user(self.mock_db, user_data)
        
        self.assertEqual(created_user.email, user_data.email)
        self.mock_db.add.assert_called_once()
        self.mock_db.commit.assert_called_once()
    
    def test_create_contact(self):
        contact_data = schemas.ContactCreate(name="John Doe", email="john@example.com", phone="123456789")
        user_id = 1
        
        new_contact = models.Contact(name=contact_data.name, email=contact_data.email, phone=contact_data.phone, owner_id=user_id)
        
        self.mock_db.add.return_value = None
        self.mock_db.commit.return_value = None
        self.mock_db.refresh.return_value = new_contact
        
        created_contact = crud.create_contact(self.mock_db, contact_data, user_id)
        
        self.assertEqual(created_contact.name, contact_data.name)
        self.mock_db.add.assert_called_once()
        self.mock_db.commit.assert_called_once()

if __name__ == "__main__":
    unittest.main()
