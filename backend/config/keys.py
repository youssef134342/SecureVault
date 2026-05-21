"""
Server-level RSA key pair for signing documents.
Also manages per-user signing keys stored in DB.
"""
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'keys')
SERVER_PRIV = os.path.join(KEYS_DIR, 'server_private.pem')
SERVER_PUB  = os.path.join(KEYS_DIR, 'server_public.pem')

def init_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(SERVER_PRIV):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(SERVER_PRIV, 'wb') as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        with open(SERVER_PUB, 'wb') as f:
            f.write(priv.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("✅ Server RSA key pair generated")

def load_server_private_key():
    with open(SERVER_PRIV, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_server_public_key():
    with open(SERVER_PUB, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def generate_user_keypair():
    """Generate an RSA key pair for a user and return PEM strings."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
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
