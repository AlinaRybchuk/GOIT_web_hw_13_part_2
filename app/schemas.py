from pydantic import BaseModel

class ContactBase(BaseModel):
    name: str
    email: str
    phone: str

class ContactCreate(ContactBase):
    pass

class ContactUpdate(ContactBase):
    pass

class Contact(ContactBase):
    id: int

    class Config:
       from_attributes = True

class UserCreate(BaseModel):
    email: str
    password: str

class User(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True
