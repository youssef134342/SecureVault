"""
Database configuration and initialization using SQLite.
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'database', 'vault.db')

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cur = conn.cursor()

    def _backfill_totp_secrets():
        """Ensure every user has a TOTP seed (mandatory 2FA; fixes legacy rows)."""
        from utils.crypto import generate_totp_secret
        cur.execute(
            "SELECT id FROM users WHERE totp_secret IS NULL OR TRIM(COALESCE(totp_secret, '')) = ''"
        )
        rows = cur.fetchall()
        for (uid,) in rows:
            cur.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=1 WHERE id=?",
                (generate_totp_secret(), uid)
            )
        if rows:
            conn.commit()
            print(f"✅ Assigned TOTP secrets to {len(rows)} user(s) missing a seed")

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid        TEXT UNIQUE NOT NULL,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT,
            role        TEXT NOT NULL DEFAULT 'user',
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            oauth_provider TEXT,
            oauth_id    TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            is_active   INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS documents (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid         TEXT UNIQUE NOT NULL,
            owner_id     INTEGER NOT NULL,
            filename     TEXT NOT NULL,
            original_name TEXT NOT NULL,
            file_size    INTEGER,
            file_type    TEXT,
            encrypted_key TEXT NOT NULL,
            iv           TEXT NOT NULL,
            sha256_hash  TEXT NOT NULL,
            signature    TEXT NOT NULL,
            signer_key_id TEXT,
            uploaded_at  TEXT DEFAULT (datetime('now')),
            is_deleted   INTEGER DEFAULT 0,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS signing_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id      TEXT UNIQUE NOT NULL,
            user_id     INTEGER,
            public_key  TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            action     TEXT NOT NULL,
            target     TEXT,
            ip_address TEXT,
            timestamp  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    conn.commit()

    # Create default admin user
    from werkzeug.security import generate_password_hash
    import uuid as uuid_lib
    cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not cur.fetchone():
        from utils.crypto import generate_totp_secret
        admin_totp = generate_totp_secret()
        cur.execute("""
            INSERT INTO users (uuid, username, email, password, role, totp_secret, totp_enabled)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        """, (
            str(uuid_lib.uuid4()),
            'admin',
            'admin@securevault.local',
            generate_password_hash('Admin@123456', method='pbkdf2:sha256:600000'),
            'admin',
            admin_totp
        ))
        conn.commit()
        print("✅ Default admin created: admin / Admin@123456 (TOTP seed assigned — scan QR at first login)")

    _backfill_totp_secrets()

    conn.close()
