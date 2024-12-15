from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, HTTPException
from fastapi.params import Depends
from fastapi.security import OAuth2PasswordRequestForm
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth.schemas import Token, User
from auth.security import ACCESS_TOKEN_EXPIRE_MINUTES, \
    DEFAULT_URL, authenticate_user, \
    create_access_token, get_current_user, oauth2_scheme, verify_token, \
    invalidate_token
from tests.auth.fake_data import fake_users_db

auth_router = APIRouter(prefix=DEFAULT_URL, tags=['Authentication'])


@auth_router.post('', summary='Login for access token')
async def login_for_access_token(
        form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = authenticate_user(
        fake_users_db,
        form_data.username,
        form_data.password
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={'sub': user.username},
        expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type='bearer')


@auth_router.get('', summary='Current User Info', response_model=User)
async def get_current_user(
        current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user


@auth_router.delete('', summary='Logout')
async def logout(token: Annotated[str, Depends(oauth2_scheme)]):
    invalidate_token(token)
    return JSONResponse(
        content={'detail': 'Token revoked'},
        status_code=status.HTTP_401_UNAUTHORIZED
    )
