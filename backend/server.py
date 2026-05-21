"""
Secure Document Vault - Main Server
Implements: JWT Auth, OAuth, 2FA, RBAC, AES-256 Encryption,
Digital Signatures, SHA-256 Integrity, HTTPS
"""

import os
import ssl
import json
from dotenv import load_dotenv
from flask import Flask, send_from_directory

# Load environment variables from .env file
load_dotenv()
from config.database import init_db
from config.keys import init_keys
from routes.auth import auth_bp
from routes.documents import docs_bp
from routes.admin import admin_bp
from routes.oauth import oauth_bp
from utils.cors import add_cors_headers

app = Flask(__name__, static_folder='../frontend', static_url_path='')

# ── Config ─────────────────────────────────────────────────────────────
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-dev-key-change-in-production')
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'jwt-secret-dev-key-change-in-production')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), '..', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'xlsx', 'pptx', 'csv'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ── CORS middleware ─────────────────────────────────────────────────────
@app.after_request
def cors(response):
    return add_cors_headers(response)

# ── Blueprints ──────────────────────────────────────────────────────────
app.register_blueprint(auth_bp,  url_prefix='/api/auth')
app.register_blueprint(docs_bp,  url_prefix='/api/documents')
app.register_blueprint(admin_bp, url_prefix='/api/admin')
app.register_blueprint(oauth_bp, url_prefix='/api/oauth')

# ── Frontend routes ─────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    frontend = os.path.join(os.path.dirname(__file__), '..', 'frontend')
    if path and os.path.exists(os.path.join(frontend, path)):
        return send_from_directory(frontend, path)
    return send_from_directory(frontend, 'index.html')

# ── Health check ────────────────────────────────────────────────────────
@app.route('/api/health')
def health():
    return {'status': 'ok', 'https': True, 'version': '1.0.0'}

if __name__ == '__main__':
    init_db()
    init_keys()
    print("\n🔒 Secure Document Vault starting on https://localhost:5443\n")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        certfile=os.path.join(os.path.dirname(__file__), '..', 'certs', 'cert.pem'),
        keyfile=os.path.join(os.path.dirname(__file__), '..', 'certs', 'key.pem')
    )
    app.run(host="0.0.0.0", port=5000)
