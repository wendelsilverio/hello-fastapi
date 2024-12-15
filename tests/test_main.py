import os
import subprocess
from datetime import timedelta

import mock
from starlette.testclient import TestClient

import main
from main import app
from fastapi import status

client = TestClient(app)


def test_root():
    response = client.get('/')
    assert response.status_code == 200
    assert response.json() == {'message': 'Hello World'}


def test_static_file():
    response = client.get('/static/favicon.ico')
    assert response.status_code == status.HTTP_200_OK


def test_get_protected_route():
    response = client.get('/protected-route')
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# Security ---------------------------------------------------------------------

def test_get_token_success():
    response = client.post(
        '/token',
        data={'username': 'johndoe', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert response.status_code == status.HTTP_200_OK
    token_data = response.json()
    assert 'access_token' in token_data
    assert token_data['access_token'].startswith(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
    assert token_data['token_type'] == 'bearer'


def test_get_token_invalid_username():
    response = client.post(
        '/token',
        data={'username': 'otheruser', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {'detail': 'Incorrect username or password'}


def test_get_token_invalid_password():
    response = client.post(
        '/token',
        data={'username': 'johndoe', 'password': 'wrong password'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {'detail': 'Incorrect username or password'}


def test_protected_route_invalid_token():
    response = client.get(
        '/protected-route',
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {'detail': 'Not authenticated'}


def test_protected_route_success():
    # Primeiro, obtenha o token
    token_response = client.post(
        '/token',
        data={'username': 'johndoe', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    token = token_response.json()['access_token']

    # Em seguida, use o token na rota protegida
    response = client.get(
        '/protected-route',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['token'].startswith(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')


def test_get_password_hash():
    print(main.get_password_hash('secret2'))
    assert main.get_password_hash('secret').startswith('$2b$12$')


def test_create_access_token():
    access_token = main.create_access_token(data={'msg': 'hello'})
    assert access_token.startswith('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')

def test_get_current_user():
    token_response = client.post(
        '/token',
        data={'username': 'johndoe', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    token = token_response.json()['access_token']

    response = client.get(
        '/users/me',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['username'] == 'johndoe'

def test_read_own_items():
    token_response = client.post(
        '/token',
        data={'username': 'johndoe', 'password': 'secret'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    token = token_response.json()['access_token']

    response = client.get(
        '/users/me/items',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()[0]['item_id'] == 'Foo'


def test_get_current_user_from_invalid_token():
    response = client.get(
        '/users/me',
        headers={'Authorization': f"Bearer 123"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_user_from_token_with_none_user():
    access_token_expires = timedelta(minutes=main.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = main.create_access_token(
        data={'sub': ''},
        expires_delta=access_token_expires
    )
    response = client.get(
        '/users/me',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_user_from_token_with_invalid_user():
    access_token_expires = timedelta(minutes=main.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = main.create_access_token(
        data={'sub': 'impostor'},
        expires_delta=access_token_expires
    )
    response = client.get(
        '/users/me',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

def test_get_current_active_user_disabled():
    token_response = client.post(
        '/token',
        data={'username': 'alice', 'password': 'secret2'},
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    token = token_response.json()['access_token']

    response = client.get(
        '/users/me/items',
        headers={'Authorization': f"Bearer {token}"}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
