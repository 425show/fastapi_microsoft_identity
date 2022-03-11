# Sample Test passing with nose and pytest
import pytest
from fastapi import Request
import sys
import os

container_folder = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..'
))
sys.path.insert(0, container_folder)

from fastapi_microsoft_identity import auth_service, AuthError
from multidict import MultiDict

user_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imk2bEdrM0ZaenhSY1ViMkMzbkVRN3N5SEpsWSJ9.eyJhdWQiOiI2ZTc0MTcyYi1iZTU2LTQ4NDMtOWZmNC1lNjZhMzliYjEyZTMiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3L3YyLjAiLCJpYXQiOjE1MzcyMzEwNDgsIm5iZiI6MTUzNzIzMTA0OCwiZXhwIjoxNTM3MjM0OTQ4LCJhaW8iOiJBWFFBaS84SUFBQUF0QWFaTG8zQ2hNaWY2S09udHRSQjdlQnE0L0RjY1F6amNKR3hQWXkvQzNqRGFOR3hYZDZ3TklJVkdSZ2hOUm53SjFsT2NBbk5aY2p2a295ckZ4Q3R0djMzMTQwUmlvT0ZKNGJDQ0dWdW9DYWcxdU9UVDIyMjIyZ0h3TFBZUS91Zjc5UVgrMEtJaWpkcm1wNjlSY3R6bVE9PSIsImF6cCI6IjZlNzQxNzJiLWJlNTYtNDg0My05ZmY0LWU2NmEzOWJiMTJlMyIsImF6cGFjciI6IjAiLCJuYW1lIjoiQWJlIExpbmNvbG4iLCJvaWQiOiI2OTAyMjJiZS1mZjFhLTRkNTYtYWJkMS03ZTRmN2QzOGU0NzQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhYmVsaUBtaWNyb3NvZnQuY29tIiwicmgiOiJJIiwic2NwIjoiYWNjZXNzX2FzX3VzZXIiLCJzdWIiOiJIS1pwZmFIeVdhZGVPb3VZbGl0anJJLUtmZlRtMjIyWDVyclYzeERxZktRIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidXRpIjoiZnFpQnFYTFBqMGVRYTgyUy1JWUZBQSIsInZlciI6IjIuMCJ9.pj4N-w_3Us9DrBLfpCt"
application_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik1yNS1BVWliZkJpaTdOZDFqQmViYXhib1hXMCJ9.eyJhdWQiOiJkZTI2NTZlNi01ODVmLTQ2ODQtOGU2NS0zY2U1MGE3NzcwYTgiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vNjZiYTk0NzYtMDcwMC00MTc4LTgxZWEtZmJlYjcwOTdjMjhlL3YyLjAiLCJpYXQiOjE2NDYxNjc1NzIsIm5iZiI6MTY0NjE2NzU3MiwiZXhwIjoxNjQ2MTcxNDcyLCJhaW8iOiJFMlpnWVBoN2RoSFBLNGNuOFE1TUFob01CenAwQVE9PSIsImF6cCI6ImY3NTllY2FiLWM0NWUtNDVlZS1hYWZmLWJlMzJhZmM3ZGU5YiIsImF6cGFjciI6IjEiLCJvaWQiOiIyMTJkOGM2ZS05YzdmLTQ4MWEtOGZkOC1kOTllMzVhOWNiMWMiLCJyaCI6IjAuQVZBQWRwUzZaZ0FIZUVHQjZ2dnJjSmZDanVaV0p0NWZXSVJHam1VODVRcDNjS2hfQUFBLiIsInJvbGVzIjpbImFwcC53ZWF0aGVyLnJlYWQiXSwic3ViIjoiMjEyZDhjNmUtOWM3Zi00ODFhLThmZDgtZDk5ZTM1YTljYjFjIiwidGlkIjoiNjZiYTk0NzYtMDcwMC00MTc4LTgxZWEtZmJlYjcwOTdjMjhlIiwidXRpIjoiX1lYOWhSbElvMGVwX2c3bk9KeXpBUSIsInZlciI6IjIuMCJ9.omq5Abe7rObD_-NDZ64KB3hf3pfCOCS4Sk3cz-jA_4cd49zwzq7wOI8CtXq5vhLUpbwRGCGiZqG-WYmTrTmDwNn2KcsEL8SQkKK5FCOriit8PrDVBAbidAAZsp8OgchhuNBdzp4wUUB7X3cQPk2g6XVOchqvw6MJZVFxi8r5Kqxq8AMJJlHO-ijUX5qKRcrIHkhezFjtGs-TV1dgdpGshKcWhpA635ehRFigY0Hry6vyYaPuiwufp2iMXJ1ZT6ZHqFIE_HeQNLTo39zV5CzVQ4UHH9gDMHfqSbEEO79JyZfNF_HjH40fmvj5HKA8nOEL_LG7fFy3p4BPiVAeUqeUvw"

auth_service.initialize(
    "66ba9476-0700-4178-81ea-fbeb7097c28e", 
    "de2656e6-585f-4684-8e65-3ce50a7770a8")

def test_auth_header_has_token():
    headers_with_auth = MultiDict([("Authorization", f'Bearer {user_token}'), ("Content-Type", "application/json")])
    request = Request
    request.headers = headers_with_auth
    token = auth_service.get_token_auth_header(request)
    assert token != None, "Retrieve token from auth header!"

def test_auth_header_is_missing():
    headers_with_no_auth = MultiDict([("Content-Type", "application/json")])
    request = Request
    request.headers = headers_with_no_auth
    with pytest.raises(AuthError):
        auth_service.get_token_auth_header(request)

def test_can_find_user_scope():
    expected_scope = "access_as_user"
    headers_with_auth = MultiDict([("Authorization", f'Bearer {user_token}'), ("Content-Type", "application/json")])
    request = Request
    request.headers = headers_with_auth
    auth_service.validate_scope(expected_scope,request,False)

def test_can_find_user_scope_but_is_wrong():
    expected_scope = "access_as_user2"
    headers_with_auth = MultiDict([("Authorization", f'Bearer {user_token}'), ("Content-Type", "application/json")])
    request = Request
    request.headers = headers_with_auth
    with pytest.raises(AuthError) as e:
        auth_service.validate_scope(expected_scope,request,False)
    assert "IDW10203" in e.value.error_msg

def test_can_find_application_role():
    expected_scope = "app.weather.read"
    headers_with_auth = MultiDict([("Authorization", f'Bearer {application_token}'), ("Content-Type", "application/json")])
    request = Request
    request.headers = headers_with_auth
    auth_service.validate_scope(expected_scope,request,True)

def test_can_find_application_role_but_is_wrong():
    expected_scope = "access_as_user"
    headers_with_auth = MultiDict([("Authorization", f'Bearer {application_token}'), ("Content-Type", "application/json")])
    request = Request
    request.headers = headers_with_auth
    with pytest.raises(AuthError) as e:
        auth_service.validate_scope(expected_scope,request,True)
    assert "IDW10203" in e.value.error_msg
