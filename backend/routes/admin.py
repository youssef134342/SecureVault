"""
Admin routes:
- List all users
- Change user roles
- Activate/deactivate users
- View audit logs
"""
from flask import Blueprint, request, jsonify, g
from config.database import get_db
from middleware.auth import token_required, role_required
from utils.audit import log_action

admin_bp = Blueprint('admin', __name__)


# ─── List Users ───────────────────────────────────────────────────────────────

@admin_bp.route('/users', methods=['GET', 'OPTIONS'])
@role_required('admin')
def list_users():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    db = get_db()
    users = db.execute("""
        SELECT id, uuid, username, email, role, totp_enabled, oauth_provider, created_at, is_active
        FROM users ORDER BY created_at DESC
    """).fetchall()
    db.close()
    return jsonify({'users': [dict(u) for u in users]})


# ─── Get User ────────────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>', methods=['GET', 'OPTIONS'])
@role_required('admin')
def get_user(user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    db = get_db()
    user = db.execute("""
        SELECT id, uuid, username, email, role, totp_enabled, oauth_provider, created_at, is_active
        FROM users WHERE id=?
    """, (user_id,)).fetchone()
    db.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'user': dict(user)})


# ─── Update Role ─────────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/role', methods=['PUT', 'OPTIONS'])
@role_required('admin')
def update_role(user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    new_role = data.get('role')
    if new_role not in ('admin', 'manager', 'user'):
        return jsonify({'error': 'Invalid role. Must be: admin, manager, user'}), 400

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404

    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    db.commit()
    log_action(g.current_user['id'], 'CHANGE_ROLE', f"user_id={user_id} -> {new_role}")
    db.close()

    return jsonify({'message': f'Role updated to {new_role}'})


# ─── Activate / Deactivate ───────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>/status', methods=['PUT', 'OPTIONS'])
@role_required('admin')
def update_status(user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json() or {}
    is_active = 1 if data.get('is_active') else 0

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404

    db.execute("UPDATE users SET is_active=? WHERE id=?", (is_active, user_id))
    db.commit()
    action = 'ACTIVATE_USER' if is_active else 'DEACTIVATE_USER'
    log_action(g.current_user['id'], action, f"user_id={user_id}")
    db.close()

    status_str = 'activated' if is_active else 'deactivated'
    return jsonify({'message': f'User {status_str} successfully'})


# ─── Delete User ─────────────────────────────────────────────────────────────

@admin_bp.route('/users/<int:user_id>', methods=['DELETE', 'OPTIONS'])
@role_required('admin')
def delete_user(user_id):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({'error': 'User not found'}), 404

    if user_id == g.current_user['id']:
        db.close()
        return jsonify({'error': 'Cannot delete your own account'}), 400

    db.execute("UPDATE users SET is_active=0 WHERE id=?", (user_id,))
    db.commit()
    log_action(g.current_user['id'], 'DELETE_USER', user['username'])
    db.close()

    return jsonify({'message': 'User deactivated'})


# ─── Audit Logs ──────────────────────────────────────────────────────────────

@admin_bp.route('/audit-logs', methods=['GET', 'OPTIONS'])
@role_required('admin')
def audit_logs():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    limit = min(int(request.args.get('limit', 100)), 500)
    db = get_db()
    logs = db.execute("""
        SELECT al.*, u.username
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()
    db.close()

    return jsonify({'logs': [dict(l) for l in logs]})


# ─── Stats ───────────────────────────────────────────────────────────────────

@admin_bp.route('/stats', methods=['GET', 'OPTIONS'])
@role_required('admin', 'manager')
def stats():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    db = get_db()
    total_users     = db.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    total_docs      = db.execute("SELECT COUNT(*) FROM documents WHERE is_deleted=0").fetchone()[0]
    total_admins    = db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0]
    total_managers  = db.execute("SELECT COUNT(*) FROM users WHERE role='manager' AND is_active=1").fetchone()[0]
    total_regular   = db.execute("SELECT COUNT(*) FROM users WHERE role='user' AND is_active=1").fetchone()[0]
    recent_uploads  = db.execute("""
        SELECT COUNT(*) FROM documents
        WHERE is_deleted=0 AND uploaded_at >= datetime('now', '-7 days')
    """).fetchone()[0]
    db.close()

    return jsonify({
        'users': {
            'total': total_users,
            'admins': total_admins,
            'managers': total_managers,
            'regular': total_regular
        },
        'documents': {
            'total': total_docs,
            'recent_7_days': recent_uploads
        }
    })
