
from main import app
from fastapi import status
from fastapi.testclient import TestClient

client = TestClient(app)


def test_root():
    response = client.get('/api/v1')
    assert response.status_code == 200
    assert response.json() == {'message': 'Hello World'}


def test_static_file():
    response = client.get('/api/v1/static/favicon.ico')
    assert response.status_code == status.HTTP_200_OK


def test_get_protected_route():
    response = client.get('/protected-route')
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


# Security ---------------------------------------------------------------------


def test_protected_route_invalid_token():
    response = client.get(
        '/protected-route',
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {'detail': 'Not authenticated'}


