"""
JWT Authentication Middleware
"""
import jwt
import os
from functools import wraps
from flask import request, jsonify, current_app, g
from config.database import get_db

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token:
            return jsonify({'error': 'Access token required'}), 401
        try:
            payload = jwt.decode(token, current_app.config['JWT_SECRET'], algorithms=['HS256'])
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id=? AND is_active=1", (payload['user_id'],)).fetchone()
            db.close()
            if not user:
                return jsonify({'error': 'User not found or inactive'}), 401
            g.current_user = dict(user)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @token_required
        def decorated(*args, **kwargs):
            if g.current_user['role'] not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
