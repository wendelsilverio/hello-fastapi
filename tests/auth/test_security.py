import auth
import auth.security


def test_get_password_hash():
    print(auth.security.get_password_hash('secret2'))
    assert auth.security.get_password_hash('secret').startswith('$2b$12$')


def test_create_access_token():
    access_token = auth.security.create_access_token(data={'msg': 'hello'})
    assert access_token.startswith('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9')
