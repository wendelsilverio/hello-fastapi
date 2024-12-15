from datetime import timedelta

import pytest
from starlette import status

import auth
import auth.security
from auth.security import ACCESS_TOKEN_EXPIRE_MINUTES

from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


@pytest.fixture
def get_token():
    post_response = client.post(
        '/auth',
        data={'username': 'johndoe', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert post_response.status_code == status.HTTP_200_OK
    assert post_response.json()['token_type'] == 'bearer'
    return post_response.json()['access_token']


def test_get_token_success(get_token):
    assert get_token.startswith('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')


def test_get_token_invalid_username():
    response = client.post(
        '/auth',
        data={'username': 'otheruser', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {'detail': 'Incorrect username or password'}


def test_get_token_invalid_password():
    response = client.post(
        '/auth',
        data={'username': 'johndoe', 'password': 'wrong password'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {'detail': 'Incorrect username or password'}


def test_protected_route_success(get_token):
    token = get_token
    response = client.get(
        '/protected-route',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['token'] == token


def test_get_current_user(get_token):
    response = client.get(
        '/auth',
        headers={'Authorization': f"Bearer {get_token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['username'] == 'johndoe'


def test_get_current_user_from_invalid_token():
    response = client.get(
        '/auth',
        headers={'Authorization': f"Bearer 123"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_current_user_from_token_with_invalid_user():
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = auth.security.create_access_token(
        data={'sub': 'impostor'},
        expires_delta=access_token_expires
    )
    response = client.get(
        '/auth',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_current_active_user_disabled():
    token_response = client.post(
        '/auth',
        data={'username': 'alice', 'password': 'secret2'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    token = token_response.json()['access_token']

    response = client.get(
        '/auth',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_logout(get_token):
    token = get_token
    get_response = client.get(
        '/auth',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert get_response.status_code == status.HTTP_200_OK

    delete_response = client.delete(
        '/auth',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert delete_response.status_code == status.HTTP_401_UNAUTHORIZED

    get_response = client.get(
        '/auth',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert get_response.status_code == status.HTTP_401_UNAUTHORIZED
