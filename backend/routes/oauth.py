"""
OAuth 2.0 Integration Routes
Supports GitHub and Google OAuth login.

For a real deployment, configure:
  GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET

In development/demo mode, this file demonstrates the OAuth flow structure.
"""
import uuid
import os
import json
import urllib.parse
import urllib.request
from flask import Blueprint, request, jsonify, redirect, current_app
from werkzeug.security import generate_password_hash
from urllib.parse import urlencode

from config.database import get_db
from utils.tokens import generate_access_token, generate_refresh_token
from utils.crypto import generate_rsa_keypair, generate_totp_secret, generate_totp_uri
from utils.audit import log_action

oauth_bp = Blueprint('oauth', __name__)

GITHUB_CLIENT_ID     = os.environ.get('GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')
GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

BASE_URL = os.environ.get('BASE_URL', 'https://localhost:5443')


# ─── GitHub OAuth ─────────────────────────────────────────────────────────────

@oauth_bp.route('/github', methods=['GET'])
def github_login():
    if not GITHUB_CLIENT_ID:
        return jsonify({
            'error': 'GitHub OAuth not configured',
            'instructions': 'Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables',
            'setup_url': 'https://github.com/settings/developers'
        }), 503

    params = urllib.parse.urlencode({
        'client_id': GITHUB_CLIENT_ID,
        'redirect_uri': f'{BASE_URL}/api/oauth/github/callback',
        'scope': 'user:email',
        'state': str(uuid.uuid4())
    })
    return redirect(f'https://github.com/login/oauth/authorize?{params}')


@oauth_bp.route('/github/callback', methods=['GET'])
def github_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'No authorization code provided'}), 400

    if not GITHUB_CLIENT_ID:
        return jsonify({'error': 'GitHub OAuth not configured'}), 503

    # Exchange code for token
    try:
        token_data = urllib.parse.urlencode({
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code
        }).encode()

        req = urllib.request.Request(
            'https://github.com/login/oauth/access_token',
            data=token_data,
            headers={'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
        )
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, context=ctx) as resp:
            token_resp = json.loads(resp.read().decode())

        gh_token = token_resp.get('access_token')
        if not gh_token:
            return jsonify({'error': 'Failed to get GitHub access token'}), 400

        # Get user info
        user_req = urllib.request.Request(
            'https://api.github.com/user',
            headers={
                'Authorization': f'Bearer {gh_token}',
                'Accept': 'application/json',
                'User-Agent': 'SecureVault'
            }
        )
        with urllib.request.urlopen(user_req, context=ctx) as resp:
            gh_user = json.loads(resp.read().decode())

        oauth_id  = str(gh_user.get('id'))
        username  = gh_user.get('login', f'gh_{oauth_id}')
        email     = gh_user.get('email') or f'{username}@github.local'
        name      = gh_user.get('name') or username

        return _oauth_login_or_register('github', oauth_id, username, email, name)

    except Exception as e:
        return jsonify({'error': f'GitHub OAuth error: {str(e)}'}), 500


# ─── Google OAuth ─────────────────────────────────────────────────────────────

@oauth_bp.route('/google', methods=['GET'])
def google_login():
    if not GOOGLE_CLIENT_ID:
        return jsonify({
            'error': 'Google OAuth not configured',
            'instructions': 'Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables',
            'setup_url': 'https://console.cloud.google.com/apis/credentials'
        }), 503

    params = urllib.parse.urlencode({
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': f'{BASE_URL}/api/oauth/google/callback',
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': str(uuid.uuid4())
    })
    return redirect(f'https://accounts.google.com/o/oauth2/v2/auth?{params}')


@oauth_bp.route('/google/callback', methods=['GET'])
def google_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'No authorization code provided'}), 400

    if not GOOGLE_CLIENT_ID:
        return jsonify({'error': 'Google OAuth not configured'}), 503

    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        token_data = urllib.parse.urlencode({
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': f'{BASE_URL}/api/oauth/google/callback',
            'grant_type': 'authorization_code'
        }).encode()

        req = urllib.request.Request(
            'https://oauth2.googleapis.com/token',
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        with urllib.request.urlopen(req, context=ctx) as resp:
            token_resp = json.loads(resp.read().decode())

        g_token = token_resp.get('access_token')
        if not g_token:
            return jsonify({'error': 'Failed to get Google access token'}), 400

        user_req = urllib.request.Request(
            f'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {g_token}'}
        )
        with urllib.request.urlopen(user_req, context=ctx) as resp:
            g_user = json.loads(resp.read().decode())

        oauth_id = str(g_user.get('id'))
        email    = g_user.get('email', f'{oauth_id}@google.local')
        name     = g_user.get('name', email.split('@')[0])
        username = email.split('@')[0].replace('.', '_')

        return _oauth_login_or_register('google', oauth_id, username, email, name)

    except Exception as e:
        return jsonify({'error': f'Google OAuth error: {str(e)}'}), 500


# ─── OAuth Info (for frontend) ────────────────────────────────────────────────

@oauth_bp.route('/providers', methods=['GET'])
def providers():
    return jsonify({
        'github': bool(GITHUB_CLIENT_ID),
        'google': bool(GOOGLE_CLIENT_ID)
    })


# ─── Shared helper ────────────────────────────────────────────────────────────

def _oauth_login_or_register(provider, oauth_id, username, email, name):
    db = get_db()

    # Check if OAuth user already exists
    user = db.execute(
        "SELECT * FROM users WHERE oauth_provider=? AND oauth_id=?",
        (provider, oauth_id)
    ).fetchone()

    if not user:
        # Try to find by email
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if user:
        # Existing user — log in
        if not user['is_active']:
            db.close()
            return redirect(f"/?error=Account+deactivated")

        access_token  = generate_access_token(user['id'], user['role'], user['username'])
        refresh_token = generate_refresh_token(user['id'])
        log_action(user['id'], f'OAUTH_LOGIN_{provider.upper()}')
        db.close()

        auth_data = {
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
        }
        encoded_message = urlencode({'message': json.dumps(auth_data)})
        return redirect(f"/pages/oauth-callback.html?{encoded_message}")

    # New user — register
    user_uuid = str(uuid.uuid4())

    # Ensure unique username
    base_username = username[:25]
    final_username = base_username
    i = 1
    while db.execute("SELECT id FROM users WHERE username=?", (final_username,)).fetchone():
        final_username = f"{base_username}_{i}"
        i += 1

    db.execute("""
        INSERT INTO users (uuid, username, email, password, role, oauth_provider, oauth_id)
        VALUES (?, ?, ?, ?, 'user', ?, ?)
    """, (user_uuid, final_username, email, None, provider, oauth_id))
    db.commit()

    user = db.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,)).fetchone()

    # Generate signing key pair
    priv_pem, pub_pem = generate_rsa_keypair()
    key_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO signing_keys (key_id, user_id, public_key, private_key) VALUES (?,?,?,?)",
        (key_id, user['id'], pub_pem, priv_pem)
    )
    db.commit()

    # Auto-enable 2FA for OAuth users (MANDATORY)
    totp_secret = generate_totp_secret()
    totp_uri = generate_totp_uri(totp_secret, final_username)
    db.execute(
        "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
        (totp_secret, user['id'])
    )
    db.commit()

    access_token  = generate_access_token(user['id'], user['role'], user['username'])
    refresh_token = generate_refresh_token(user['id'])
    log_action(user['id'], f'OAUTH_REGISTER_{provider.upper()}')
    db.close()

    auth_data = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user['id'],
            'uuid': user['uuid'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'totp_enabled': True
        },
        '2fa_setup': {
            'secret': totp_secret,
            'uri': totp_uri,
            'message': '2FA is mandatory. Scan the QR code with your authenticator app.'
        }
    }
    encoded_message = urlencode({'message': json.dumps(auth_data)})
    return redirect(f"/pages/oauth-callback.html?{encoded_message}")
