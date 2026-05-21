"""Audit logging helper."""
from config.database import get_db
from flask import request


def log_action(user_id, action, target=None):
    try:
        ip = request.remote_addr or 'unknown'
        db = get_db()
        db.execute(
            "INSERT INTO audit_logs (user_id, action, target, ip_address) VALUES (?,?,?,?)",
            (user_id, action, target, ip)
        )
        db.commit()
        db.close()
    except Exception:
        pass
