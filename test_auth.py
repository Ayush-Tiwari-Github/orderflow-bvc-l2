# OrderFlow: Authentication test suite

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import app
from auth import create_access_token, USERS_DB

client = TestClient(app)


# Pre-written — use this as a reference when writing your own fixtures below.
@pytest.fixture
def auth_token():
    return create_access_token({"sub": "alice@orderflow.com", "role": "admin"})


# Complete this fixture — it should return the Authorization header dict using the token above.
@pytest.fixture
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}


# This test checks that the products endpoint rejects requests with no credentials.
# There is a bug — identify and fix it.
def test_unauthenticated_access_rejected():
    response = client.get("/products")
    assert response.status_code == 401


# TODO: Check that a valid token gets through and the endpoint returns a non-empty product list.
def test_authenticated_access_succeeds(auth_headers):
    response = client.get("/products", headers = auth_headers)
    assert response.status_code == 200
    assert len(response.json()) > 0


# TODO: Check that a structurally invalid token string is rejected.
def test_malformed_token_rejected():
    response = client.get("/products", headers = {"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


# TODO: Verify that wrong email, wrong password, and both wrong each result in a rejected login.
# Use parametrize so all three cases run without repeating test code.
@pytest.mark.parametrize("email, password, expected_status", [
    # add your test cases here
    ("alice@orderflow.com", "wrongpassword", 401),
    ("nonexistent@orderflow.com", "secret", 401),
    ("nonexistent@orderflow.com", "wrongpassword", 401),
])
def test_login_invalid_credentials(email, password, expected_status):
    response= client.post("/auth/login", data={"username": email, "password": password})
    assert response.status_code == expected_status


# TODO: Replace the user store with a controlled test user and confirm the login endpoint
# returns a token for those credentials. This keeps the test independent of the real user data.
def test_login_with_mocked_users_db():
    from auth import pwd_context
    mock_db = {
        "test@example.com": {
            "email": "test@example.com",
            "hashed_password": pwd_context.hash("testpass123"),
            "role": "viewer",
        }
    }  # build your test user here
    with patch("auth.USERS_DB", mock_db):
        response = client.post("/auth/login", data={"username": "test@example.com", "password": "testpass123"})
        assert response.status_code == 200
        assert "access_token" in response.json()
          # call login and assert
