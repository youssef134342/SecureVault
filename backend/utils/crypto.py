"""
Cryptographic utilities:
- AES-256-GCM document encryption
- RSA-2048 digital signatures
- SHA-256 integrity hashing
- TOTP 2FA implementation
"""
import os
import secrets
import hashlib
import hmac as hmac_lib
import struct
import time
import base64
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
from cryptography.exceptions import InvalidSignature

# ── AES-256-GCM ───────────────────────────────────────────────────────

def generate_aes_key():
    """Generate a random 256-bit AES key."""
    return secrets.token_bytes(32)

def encrypt_data(plaintext: bytes) -> dict:
    """Encrypt data with AES-256-GCM. Returns base64-encoded key, iv, and ciphertext."""
    key = generate_aes_key()
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        'key': base64.b64encode(key).decode(),
        'iv': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

def decrypt_data(ciphertext_b64: str, key_b64: str, iv_b64: str) -> bytes:
    """Decrypt AES-256-GCM encrypted data."""
    key = base64.b64decode(key_b64)
    nonce = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ── SHA-256 Integrity ─────────────────────────────────────────────────

def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash and return hex string."""
    return hashlib.sha256(data).hexdigest()

def verify_sha256(data: bytes, expected_hash: str) -> bool:
    actual = compute_sha256(data)
    return hmac_lib.compare_digest(actual, expected_hash)

# ── RSA Digital Signatures ────────────────────────────────────────────

def sign_data(data: bytes, private_key_pem: str) -> str:
    """Sign data with RSA-2048 private key. Returns base64 signature."""
    priv = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    sig = priv.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode()

def verify_signature(data: bytes, signature_b64: str, public_key_pem: str) -> bool:
    """Verify RSA signature. Returns True if valid."""
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, data, asym_padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, Exception):
        return False

def generate_rsa_keypair():
    """Generate a new RSA-2048 key pair. Returns (private_pem, public_pem) strings."""
    priv = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv_pem, pub_pem

# ── TOTP 2FA (RFC 6238) ───────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Generate a random base32-encoded TOTP secret."""
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode()

def get_totp_code(secret: str, timestamp: int = None, step: int = 30) -> str:
    """Compute the TOTP code for a given secret at a given time."""
    if timestamp is None:
        timestamp = int(time.time())
    counter = timestamp // step
    key = base64.b32decode(secret.upper().replace(' ', ''))
    msg = struct.pack('>Q', counter)
    h = hmac_lib.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0f
    code = struct.unpack('>I', h[offset:offset + 4])[0] & 0x7fffffff
    return str(code % 1_000_000).zfill(6)

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code allowing ±window time steps."""
    now = int(time.time())
    for delta in range(-window, window + 1):
        expected = get_totp_code(secret, now + delta * 30)
        if hmac_lib.compare_digest(expected, str(code).zfill(6)):
            return True
    return False

def _uri_str(value) -> str:
    """Coerce DB / API values to str for urllib.parse.quote (Py3.14+ rejects non-str)."""
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)


def generate_totp_uri(secret: str, username: str, issuer: str = 'SecureVault') -> str:
    """Generate an otpauth:// URI for QR code generation (label and issuer URL-encoded)."""
    secret_s = _uri_str(secret).strip()
    username_s = _uri_str(username).strip()
    issuer_s = (_uri_str(issuer).strip() or 'SecureVault')
    label = f'{issuer_s}:{username_s}'
    return (
        f'otpauth://totp/{quote(label, safe="")}'
        f'?secret={quote(secret_s, safe="")}&issuer={quote(issuer_s, safe="")}'
        f'&algorithm=SHA1&digits=6&period=30'
    )

def totp_uri_to_qr_dataurl(uri: str) -> str:
    """
    Return a simple text representation of the TOTP URI.
    (qrcode library not available; user can use external QR generator)
    """
    return uri

# ── Password Policy ───────────────────────────────────────────────────

def validate_password(password: str) -> tuple[bool, str]:
    """
    Enforce password policy:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"
    return True, "OK"
