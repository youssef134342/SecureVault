"""
Authentication routes:
- Register, Login, Logout
- 2FA setup and verification
- Password change
- Token refresh
"""
import uuid
import datetime
from flask import Blueprint, request, jsonify, g, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from config.database import get_db
from utils.crypto import (
    validate_password, generate_totp_secret, verify_totp,
    generate_totp_uri, generate_rsa_keypair
)
from utils.tokens import generate_access_token, generate_refresh_token
from utils.audit import log_action
from middleware.auth import token_required

auth_bp = Blueprint('auth', __name__)


# ─── Register ────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    email    = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    role     = data.get('role', 'user')

    if not username or not email or not password:
        return jsonify({'error': 'username, email and password are required'}), 400

    if len(username) < 3 or len(username) > 30:
        return jsonify({'error': 'Username must be 3–30 characters'}), 400

    if '@' not in email:
        return jsonify({'error': 'Invalid email address'}), 400

    valid, msg = validate_password(password)
    if not valid:
        return jsonify({'error': msg}), 400

    if role not in ('user', 'manager', 'admin'):
        role = 'user'

    db = get_db()
    if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
        db.close()
        return jsonify({'error': 'Username already taken'}), 409

    if db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        db.close()
        return jsonify({'error': 'Email already registered'}), 409

    pw_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
    user_uuid = str(uuid.uuid4())

    db.execute("""
        INSERT INTO users (uuid, username, email, password, role)
        VALUES (?, ?, ?, ?, ?)
    """, (user_uuid, username, email, pw_hash, role))
    db.commit()

    user = db.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,)).fetchone()

    # Generate user signing key pair
    priv_pem, pub_pem = generate_rsa_keypair()
    key_id = str(uuid.uuid4())
    db.execute("""
        INSERT INTO signing_keys (key_id, user_id, public_key, private_key)
        VALUES (?, ?, ?, ?)
    """, (key_id, user['id'], pub_pem, priv_pem))
    db.commit()

    # Auto-enable 2FA for all users (MANDATORY)
    totp_secret = generate_totp_secret()
    totp_uri = generate_totp_uri(totp_secret, username)
    db.execute(
        "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
        (totp_secret, user['id'])
    )
    db.commit()

    log_action(user['id'], 'REGISTER', username)
    db.close()

    return jsonify({
        'message': 'Account created successfully. 2FA is mandatory.',
        'uuid': user_uuid,
        '2fa_secret': totp_secret,
        '2fa_uri': totp_uri,
        '2fa_required': True,
        'instructions': 'Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.) or enter the secret manually.'
    }), 201


# ─── Login ───────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    totp_code = data.get('totp_code') or ''

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1",
        (username, username)
    ).fetchone()

    if not user or not user['password'] or not check_password_hash(user['password'], password):
        log_action(None, 'LOGIN_FAIL', username)
        db.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # 2FA is MANDATORY for all users
    if not totp_code:
        # Legacy / seed users (e.g. default admin) may have no secret yet — provision one
        if not user['totp_secret'] or not str(user['totp_secret']).strip():
            new_secret = generate_totp_secret()
            db.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                (new_secret, user['id'])
            )
            db.commit()
            user = db.execute("SELECT * FROM users WHERE id=?", (user['id'],)).fetchone()

        totp_uri = generate_totp_uri(user['totp_secret'], user['username'])
        db.close()
        return jsonify({
            'require_2fa': True,
            'message': '2FA code is required',
            'secret': user['totp_secret'],
            'uri': totp_uri
        }), 200
    if not verify_totp(user['totp_secret'], totp_code):
        log_action(user['id'], '2FA_FAIL', username)
        db.close()
        return jsonify({'error': 'Invalid 2FA code'}), 401

    access_token  = generate_access_token(user['id'], user['role'], user['username'])
    refresh_token = generate_refresh_token(user['id'])
    log_action(user['id'], 'LOGIN', username)
    db.close()

    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user['id'],
            'uuid': user['uuid'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'totp_enabled': True
        }
    })


# ─── Logout ──────────────────────────────────────────────────────────────────

@auth_bp.route('/logout', methods=['POST', 'OPTIONS'])
@token_required
def logout():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    log_action(g.current_user['id'], 'LOGOUT')
    return jsonify({'message': 'Logged out successfully'})


# ─── Profile ─────────────────────────────────────────────────────────────────

@auth_bp.route('/me', methods=['GET', 'OPTIONS'])
@token_required
def me():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    u = g.current_user
    return jsonify({
        'id': u['id'],
        'uuid': u['uuid'],
        'username': u['username'],
        'email': u['email'],
        'role': u['role'],
        'totp_enabled': True,
        'created_at': u['created_at']
    })


# ─── Change Password ──────────────────────────────────────────────────────────

@auth_bp.route('/change-password', methods=['POST', 'OPTIONS'])
@token_required
def change_password():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    old_pw = data.get('old_password') or ''
    new_pw = data.get('new_password') or ''

    if not old_pw or not new_pw:
        return jsonify({'error': 'old_password and new_password required'}), 400

    valid, msg = validate_password(new_pw)
    if not valid:
        return jsonify({'error': msg}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (g.current_user['id'],)).fetchone()

    if not check_password_hash(user['password'], old_pw):
        db.close()
        return jsonify({'error': 'Incorrect current password'}), 401

    new_hash = generate_password_hash(new_pw, method='pbkdf2:sha256:600000')
    db.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user['id']))
    db.commit()
    log_action(user['id'], 'CHANGE_PASSWORD')
    db.close()

    return jsonify({'message': 'Password updated successfully'})


# ─── 2FA Setup ───────────────────────────────────────────────────────────────

@auth_bp.route('/2fa/setup', methods=['POST', 'OPTIONS'])
@token_required
def setup_2fa():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    secret = generate_totp_secret()
    uri = generate_totp_uri(secret, g.current_user['username'])

    db = get_db()
    db.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, g.current_user['id']))
    db.commit()
    db.close()

    return jsonify({
        'secret': secret,
        'uri': uri,
        'message': 'Scan the QR code or enter the secret manually in your authenticator app',
        'instructions': 'Use Google Authenticator, Authy, or any TOTP app. Enter the 6-digit code below to confirm.'
    })


@auth_bp.route('/2fa/enable', methods=['POST', 'OPTIONS'])
@token_required
def enable_2fa():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    code = data.get('code') or ''

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (g.current_user['id'],)).fetchone()

    if not user['totp_secret']:
        db.close()
        return jsonify({'error': 'Run /2fa/setup first'}), 400

    if not verify_totp(user['totp_secret'], code):
        db.close()
        return jsonify({'error': 'Invalid code. Please try again.'}), 400

    db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (user['id'],))
    db.commit()
    log_action(user['id'], '2FA_ENABLED')
    db.close()

    return jsonify({'message': '2FA enabled successfully'})


# NOTE: 2FA is MANDATORY and cannot be disabled
# Users must always use 2FA to log in
