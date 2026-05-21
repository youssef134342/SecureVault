"""
Document management routes:
- Upload (encrypt + sign + hash)
- Download (decrypt)
- List, View metadata, Delete
- Integrity verification
"""
import os
import uuid
import json
import base64
from flask import Blueprint, request, jsonify, g, send_file, current_app
from werkzeug.utils import secure_filename
import io

from config.database import get_db
from middleware.auth import token_required, role_required
from utils.crypto import encrypt_data, decrypt_data, compute_sha256, sign_data, verify_signature, verify_sha256
from utils.audit import log_action

docs_bp = Blueprint('documents', __name__)

ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt', 'png', 'jpg', 'jpeg', 'xlsx', 'pptx', 'csv', 'doc'}
MAX_SIZE = 16 * 1024 * 1024  # 16 MB


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_upload_path(filename):
    upload_dir = current_app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)
    return os.path.join(upload_dir, filename)


# ─── Upload ───────────────────────────────────────────────────────────────────

@docs_bp.route('/upload', methods=['POST', 'OPTIONS'])
@token_required
def upload_document():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    raw = file.read()

    if len(raw) > MAX_SIZE:
        return jsonify({'error': 'File exceeds 16 MB limit'}), 413

    if len(raw) == 0:
        return jsonify({'error': 'File is empty'}), 400

    # 1. Compute SHA-256 hash of original file
    sha256 = compute_sha256(raw)

    # 2. Encrypt with AES-256-GCM
    enc = encrypt_data(raw)

    # 3. Sign the SHA-256 hash with user's RSA private key
    db = get_db()
    user_id = g.current_user['id']
    key_row = db.execute(
        "SELECT * FROM signing_keys WHERE user_id=? ORDER BY id DESC LIMIT 1",
        (user_id,)
    ).fetchone()

    if not key_row:
        db.close()
        return jsonify({'error': 'No signing key found for user'}), 500

    signature = sign_data(sha256.encode(), key_row['private_key'])

    # 4. Store encrypted ciphertext as the "file"
    doc_uuid = str(uuid.uuid4())
    safe_name = secure_filename(file.filename)
    stored_filename = f"{doc_uuid}.enc"
    file_path = get_upload_path(stored_filename)

    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(enc['ciphertext']))

    # 5. Store metadata in DB (key and iv stored separately — never in plaintext alongside file)
    db.execute("""
        INSERT INTO documents
          (uuid, owner_id, filename, original_name, file_size, file_type,
           encrypted_key, iv, sha256_hash, signature, signer_key_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        doc_uuid,
        user_id,
        stored_filename,
        safe_name,
        len(raw),
        file.content_type or safe_name.rsplit('.', 1)[-1],
        enc['key'],
        enc['iv'],
        sha256,
        signature,
        key_row['key_id']
    ))
    db.commit()
    log_action(user_id, 'UPLOAD', safe_name)
    db.close()

    return jsonify({
        'message': 'Document uploaded and encrypted successfully',
        'document': {
            'uuid': doc_uuid,
            'original_name': safe_name,
            'file_size': len(raw),
            'sha256_hash': sha256,
            'signed': True,
            'encrypted': True
        }
    }), 201


# ─── List ─────────────────────────────────────────────────────────────────────

@docs_bp.route('/', methods=['GET', 'OPTIONS'])
@token_required
def list_documents():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    db = get_db()
    user = g.current_user

    if user['role'] in ('admin', 'manager'):
        docs = db.execute("""
            SELECT d.*, u.username as owner_username
            FROM documents d JOIN users u ON d.owner_id = u.id
            WHERE d.is_deleted=0 ORDER BY d.uploaded_at DESC
        """).fetchall()
    else:
        docs = db.execute("""
            SELECT d.*, u.username as owner_username
            FROM documents d JOIN users u ON d.owner_id = u.id
            WHERE d.owner_id=? AND d.is_deleted=0 ORDER BY d.uploaded_at DESC
        """, (user['id'],)).fetchall()

    db.close()

    return jsonify({'documents': [dict(r) for r in docs]})


# ─── Metadata ────────────────────────────────────────────────────────────────

@docs_bp.route('/<doc_uuid>', methods=['GET', 'OPTIONS'])
@token_required
def get_document_meta(doc_uuid):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    db = get_db()
    doc = db.execute("""
        SELECT d.*, u.username as owner_username
        FROM documents d JOIN users u ON d.owner_id = u.id
        WHERE d.uuid=? AND d.is_deleted=0
    """, (doc_uuid,)).fetchone()
    db.close()

    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    user = g.current_user
    if user['role'] not in ('admin', 'manager') and doc['owner_id'] != user['id']:
        return jsonify({'error': 'Access denied'}), 403

    result = dict(doc)
    result.pop('encrypted_key', None)
    result.pop('iv', None)
    return jsonify({'document': result})


# ─── Download (Decrypt) ───────────────────────────────────────────────────────

@docs_bp.route('/<doc_uuid>/download', methods=['GET', 'OPTIONS'])
@token_required
def download_document(doc_uuid):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE uuid=? AND is_deleted=0", (doc_uuid,)).fetchone()
    db.close()

    if not doc:
        return jsonify({'error': 'Document not found'}), 404

    user = g.current_user
    if user['role'] not in ('admin', 'manager') and doc['owner_id'] != user['id']:
        return jsonify({'error': 'Access denied'}), 403

    file_path = get_upload_path(doc['filename'])
    if not os.path.exists(file_path):
        return jsonify({'error': 'Encrypted file not found on disk'}), 404

    with open(file_path, 'rb') as f:
        ciphertext_bytes = f.read()

    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode()
    plaintext = decrypt_data(ciphertext_b64, doc['encrypted_key'], doc['iv'])

    log_action(user['id'], 'DOWNLOAD', doc['original_name'])

    return send_file(
        io.BytesIO(plaintext),
        download_name=doc['original_name'],
        as_attachment=True,
        mimetype=doc['file_type'] or 'application/octet-stream'
    )


# ─── Verify Integrity ─────────────────────────────────────────────────────────

@docs_bp.route('/<doc_uuid>/verify', methods=['GET', 'POST', 'OPTIONS'])
@token_required
def verify_document(doc_uuid):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    candidate_bytes = None
    if request.method == 'POST':
        pdata = request.get_json(silent=True) or {}
        b64 = pdata.get('candidate_plaintext_b64')
        if b64 is not None and str(b64).strip() != '':
            try:
                candidate_bytes = base64.b64decode(b64)
            except Exception:
                return jsonify({'error': 'Invalid candidate_plaintext_b64 (must be standard base64)'}), 400
        elif 'candidate_text' in pdata and pdata.get('candidate_text') is not None:
            candidate_bytes = str(pdata.get('candidate_text')).encode('utf-8')

    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE uuid=? AND is_deleted=0", (doc_uuid,)).fetchone()

    if not doc:
        db.close()
        return jsonify({'error': 'Document not found'}), 404

    user = g.current_user
    if user['role'] not in ('admin', 'manager') and doc['owner_id'] != user['id']:
        db.close()
        return jsonify({'error': 'Access denied'}), 403

    # Decrypt vault copy and recompute hash
    file_path = get_upload_path(doc['filename'])
    integrity_ok = False
    signature_ok = False
    current_hash = None

    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            ciphertext_bytes = f.read()
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode()
        try:
            plaintext = decrypt_data(ciphertext_b64, doc['encrypted_key'], doc['iv'])
            current_hash = compute_sha256(plaintext)
            integrity_ok = verify_sha256(plaintext, doc['sha256_hash'])
        except Exception:
            integrity_ok = False

        # Verify signature (over the original SHA-256 digest bytes recorded at upload)
        key_row = db.execute(
            "SELECT * FROM signing_keys WHERE key_id=?", (doc['signer_key_id'],)
        ).fetchone()
        if key_row:
            signature_ok = verify_signature(
                doc['sha256_hash'].encode(),
                doc['signature'],
                key_row['public_key']
            )

    db.close()
    log_action(user['id'], 'VERIFY', doc['original_name'])

    status = 'VALID' if (integrity_ok and signature_ok) else 'TAMPERED_OR_CORRUPTED'

    candidate_integrity_ok = None
    candidate_hash = None
    if candidate_bytes is not None:
        candidate_hash = compute_sha256(candidate_bytes)
        candidate_integrity_ok = verify_sha256(candidate_bytes, doc['sha256_hash'])

    payload = {
        'document_uuid': doc_uuid,
        'original_name': doc['original_name'],
        'stored_hash': doc['sha256_hash'],
        'vault_current_hash': current_hash,
        'integrity_check': integrity_ok,
        'signature_check': signature_ok,
        'overall_status': status,
        'encrypted': True,
        'signed': True,
        'candidate_provided': candidate_bytes is not None,
        'candidate_integrity_check': candidate_integrity_ok,
        'candidate_hash': candidate_hash,
    }
    return jsonify(payload)


# ─── Delete ───────────────────────────────────────────────────────────────────

@docs_bp.route('/<doc_uuid>', methods=['DELETE', 'OPTIONS'])
@token_required
def delete_document(doc_uuid):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    db = get_db()
    doc = db.execute("SELECT * FROM documents WHERE uuid=? AND is_deleted=0", (doc_uuid,)).fetchone()

    if not doc:
        db.close()
        return jsonify({'error': 'Document not found'}), 404

    user = g.current_user
    if user['role'] != 'admin' and doc['owner_id'] != user['id']:
        db.close()
        return jsonify({'error': 'Access denied'}), 403

    db.execute("UPDATE documents SET is_deleted=1 WHERE uuid=?", (doc_uuid,))
    db.commit()
    log_action(user['id'], 'DELETE', doc['original_name'])
    db.close()

    return jsonify({'message': 'Document deleted successfully'})
