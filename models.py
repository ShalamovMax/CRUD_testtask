from typing import Optional
from pydantic import BaseModel
from pymongo import MongoClient
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId, json_util
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = 'a6a5d44dfd87a5dc2d4576ed6692ff652ec6ae69b670ef40617f60e55fd009bf'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

client = MongoClient('localhost', 27017)
db = client['Emphasoft-database']
collection = db['Emphasoft-collection']


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class UserBase(BaseModel):
    username: str
    first_name: Optional[str]
    last_name: Optional[str]
    is_active: Optional[bool]


class UserIn(UserBase):
    is_superuser: bool
    password: str


class UserOut(UserBase):
    is_active: bool
    is_superuser: bool


class UserInDB(UserBase):
    is_superuser: bool = False
    hashed_password: str


class UserPatch(UserBase):
    password: Optional[str]
    is_superuser: Optional[bool]


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):
    user = collection.find_one({'username': username})
    if user:
        return UserInDB(**user)


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def user_helper(user) -> dict:
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "is_active": user["is_active"],
        "is_superuser": user["is_superuser"],
    }


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


def create_user(data) -> dict:
    data['hashed_password'] = get_password_hash(data['password'])
    data.pop('password')
    user = collection.insert_one(data)
    new_user = collection.find_one({'_id': user.inserted_id})
    print(new_user['_id'])
    return user_helper(new_user)


def get_users():
    users = []
    for user in collection.find():
        users.append(user_helper(user))
    return users


def get_user_data(_id: str) -> dict:
    user = collection.find_one({"_id": ObjectId(_id)})
    if user:
        return user_helper(user)


def update_user_data(_id: str, data):
    if len(data) < 1:  # Check body is not empty
        return False
    if 'password' in data:
        data['hashed_password'] = get_password_hash(data['password'])
        data.pop('password')
    user = collection.find_one({"_id": ObjectId(_id)})
    if user:
        updated_user = collection.update_one(
            {"_id": ObjectId(_id)}, {"$set": data}
        )
        if updated_user:
            return True
        return False


def delete_user_data(_id: str):
    user = collection.find_one({"_id": ObjectId(_id)})
    if user:
        collection.delete_one({"_id": ObjectId(_id)})
        return True
