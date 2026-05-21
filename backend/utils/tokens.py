"""JWT token generation and validation helpers."""
import jwt
import datetime
from flask import current_app


def generate_access_token(user_id: int, role: str, username: str) -> str:
    payload = {
        'user_id': user_id,
        'role': role,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=8),
        'iat': datetime.datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')


def generate_refresh_token(user_id: int) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow(),
        'type': 'refresh'
    }
    return jwt.encode(payload, current_app.config['JWT_SECRET'], algorithm='HS256')


def decode_token(token: str) -> dict:
    return jwt.decode(token, current_app.config['JWT_SECRET'], algorithms=['HS256'])
