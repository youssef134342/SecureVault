A complete secure web-based document management system implementing modern cryptographic security principles.

## Security Features

| Feature | Implementation |
|---|---|
| Password Hashing | PBKDF2-SHA256 (600,000 iterations) via Werkzeug |
| JWT Authentication | HS256 tokens (8h access / 7d refresh) |
| OAuth Login | GitHub & Google OAuth 2.0 |
| Two-Factor Auth (2FA) | TOTP RFC 6238 (Google Authenticator compatible) |
| Document Encryption | AES-256-GCM (authenticated encryption) |
| Digital Signatures | RSA-2048 + SHA-256 (PKCS#1 v1.5) |
| Integrity Verification | SHA-256 hash comparison |
| RBAC | Admin / Manager / User roles |
| HTTPS | TLS via self-signed certificate (OpenSSL) |
| Password Policy | Min 8 chars, upper, lower, digit, special |

## Prerequisites

- Python 3.10+
- pip
- OpenSSL (for certificate generation)

## Installation & Run

### 1. Clone / Extract the project

```bash
cd secure-vault
```

### 2. Install Python dependencies

```bash
pip install -r backend/requirements.txt
```

Or system-wide:
```bash
pip install Flask cryptography PyJWT Werkzeug --break-system-packages
```

### 3. Generate SSL certificates (if not present)

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -subj "/C=EG/ST=Gharbia/O=SecureVault/CN=localhost"
```

### 4. (Optional) Configure OAuth

Set environment variables for OAuth login:

```bash
# GitHub OAuth
export GITHUB_CLIENT_ID=your_github_client_id
export GITHUB_CLIENT_SECRET=your_github_client_secret

# Google OAuth
export GOOGLE_CLIENT_ID=your_google_client_id
export GOOGLE_CLIENT_SECRET=your_google_client_secret
```

**GitHub:** https://github.com/settings/developers → New OAuth App  
Callback URL: `https://localhost:5443/api/oauth/github/callback`

**Google:** https://console.cloud.google.com/apis/credentials → OAuth 2.0  
Callback URL: `https://localhost:5443/api/oauth/google/callback`

### 5. Run the server

```bash
cd backend
python server.py
```

Or from the root:
```bash
python backend/server.py
```

### 6. Open in browser

```
https://localhost:5443
```

>  Your browser will show a security warning because the certificate is self-signed.  
> Click "Advanced" → "Proceed to localhost" to continue.

## Default Admin Account

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `Admin@123456` |
| Role | Admin |

**Change the admin password immediately after first login!**

## Project Structure

```
secure-vault/
├── backend/
│   ├── server.py              # Flask app entry point
│   ├── requirements.txt       # Python dependencies
│   ├── config/
│   │   ├── database.py        # SQLite init & schema
│   │   └── keys.py            # RSA key management
│   ├── routes/
│   │   ├── auth.py            # Login, register, 2FA
│   │   ├── documents.py       # Upload, download, verify
│   │   ├── admin.py           # User/role management
│   │   └── oauth.py           # GitHub & Google OAuth
│   ├── middleware/
│   │   └── auth.py            # JWT middleware
│   └── utils/
│       ├── crypto.py          # AES-256, RSA, SHA-256, TOTP
│       ├── tokens.py          # JWT helpers
│       ├── audit.py           # Audit logging
│       └── cors.py            # CORS & security headers
├── frontend/
│   ├── index.html             # Login / Register page
│   ├── css/
│   │   ├── style.css          # Main stylesheet
│   │   └── auth.css           # Auth page styles
│   ├── js/
│   │   ├── api.js             # API client + utilities
│   │   ├── auth.js            # Login/register logic
│   │   └── dashboard.js       # Dashboard logic
│   └── pages/
│       └── dashboard.html     # Main app page
├── certs/
│   ├── cert.pem               # TLS certificate
│   └── key.pem                # TLS private key
├── database/
│   └── vault.db               # SQLite database (auto-created)
├── keys/
│   ├── server_private.pem     # Server RSA private key (auto-created)
│   └── server_public.pem      # Server RSA public key (auto-created)
└── uploads/                   # Encrypted document storage (auto-created)
```




