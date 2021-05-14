import uvicorn

from datetime import timedelta
from fastapi.encoders import jsonable_encoder
from fastapi import APIRouter, FastAPI, Depends, HTTPException, status
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordRequestForm

from models import UserIn, UserOut, Token, UserPatch, create_user, get_users, update_user_data, \
    delete_user_data, get_user_data, authenticate_user, create_access_token, get_current_user

ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
router = APIRouter()


def response_model(data, message):
    return {
        "data": [data],
        "code": 200,
        "message": message,
    }


def error_response_model(error, code, message):
    return {"error": error, "code": code, "message": message}


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/")
def users_list():
    users = get_users()
    return users


@app.get("/users/me/", response_model=UserOut)
async def read_users_me(current_user: UserOut = Depends(get_current_user)):
    return current_user


@app.post("/create")
def create_user_data(user: UserIn):
    user = jsonable_encoder(user)
    new_user = create_user(user)
    return new_user


@app.get("/users/{_id}", response_description='User data retrieved')
def user_read(_id: str):
    user = get_user_data(_id)
    return user


@app.put("/users/{_id}", response_description='User data updated')
def user_update(_id: str, user: UserIn):
    user = {k: v for k, v in user.dict().items() if v is not None}  # <class 'models.UserIn'> -> <class 'dict'>
    updated_user = update_user_data(_id, user)
    if updated_user:
        return response_model("User with ID: {} updated successfully".format(_id),
                              "User updated successfully",
                              )
    return error_response_model(
        "An error occurred",
        404,
        "There was an error updating the user data.",
    )


@app.patch("/users/{_id}", response_description='User data partially updated')
def user_partial_update(_id: str, user: UserPatch):
    user = {k: v for k, v in user.dict().items() if v is not None}  # <class 'models.UserIn'> -> <class 'dict'>
    updated_user = update_user_data(_id, user)
    if updated_user:
        return response_model("User with ID: {} updated successfully".format(_id),
                              "User updated successfully",
                              )
    return error_response_model(
        "An error occurred",
        404,
        "There was an error updating the user data.",
    )


@app.delete("/users/{_id}", response_description='User data deleted')
def user_delete(_id: str):
    deleted_user = delete_user_data(_id)
    if deleted_user:
        return response_model("User with ID: {} deleted successfully".format(_id),
                              "User deleted successfully",
                              )
    return error_response_model(
        "An error occurred",
        404,
        "User doesn't exist",
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
