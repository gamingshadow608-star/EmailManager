"""Database models and helpers for the email bot.

This module encapsulates access to a small SQLite database used by
the web application.  It defines tables for users, email accounts and
activity logs and provides helper functions to manipulate them.
"""

from __future__ import annotations

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

from passlib.hash import bcrypt
from cryptography.fernet import Fernet, InvalidToken
import base64

DB_PATH = os.path.join(os.path.dirname(__file__), "email_bot.db")


def get_db_connection() -> sqlite3.Connection:
    """Return a new connection to the database.

    The connection uses row factory so that columns can be accessed
    by name.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create database tables if they do not already exist."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            email_address TEXT NOT NULL,
            imap_server TEXT NOT NULL,
            imap_port INTEGER NOT NULL,
            smtp_server TEXT NOT NULL,
            smtp_port INTEGER NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.commit()
    conn.close()


def get_encryption_key() -> bytes:
    """Return a 32‑byte key for encryption based on an environment variable."""
    secret = os.environ.get("EMAIL_BOT_SECRET")
    if not secret:
        # If no secret provided, derive a key from a default string.  This is
        # insecure; set EMAIL_BOT_SECRET in your environment for real use.
        secret = "default_secret_key_for_email_bot"
    # Ensure the key is 32 url‑safe base64 bytes.  If the provided
    # secret is shorter, pad with zeros; if longer, truncate.
    # Generate a 32‑byte key then base64 encode.
    key = secret.encode("utf-8")
    # Use the first 32 bytes of the secret; pad if needed
    padded = key.ljust(32, b"0")[:32]
    return base64.urlsafe_b64encode(padded)


def encrypt_password(password: str) -> bytes:
    """Encrypt the given password using Fernet."""
    key = os.environ.get("EMAIL_BOT_SECRET")
    if not key:
        # Provide a fallback key if not set; for demonstration only
        key = "default_secret_key_for_email_bot"
    # Build a 32‑byte key: pad/truncate and base64 encode
    padded = key.encode("utf-8").ljust(32, b"0")[:32]
    fkey = base64.urlsafe_b64encode(padded)
    f = Fernet(fkey)
    return f.encrypt(password.encode("utf-8"))


def decrypt_password(token: bytes) -> str:
    """Decrypt the stored password token using Fernet."""
    key = os.environ.get("EMAIL_BOT_SECRET")
    if not key:
        key = "default_secret_key_for_email_bot"
    padded = key.encode("utf-8").ljust(32, b"0")[:32]
    fkey = base64.urlsafe_b64encode(padded)
    f = Fernet(fkey)
    try:
        return f.decrypt(token).decode("utf-8")
    except InvalidToken:
        return ""


def create_user(username: str, password: str, role: str = "user") -> bool:
    """Create a new user with the given username, password and role.

    Returns True if created successfully, False if username already exists.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    hashed = bcrypt.hash(password)
    try:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed, role),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    """Fetch a user row by username.  Returns None if not found."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def verify_user(username: str, password: str) -> Optional[int]:
    """Verify a username and password.

    Returns the user ID if authentication succeeds, or None otherwise.
    """
    row = get_user_by_username(username)
    if row and bcrypt.verify(password, row["password"]):
        return row["id"]
    return None


def get_user_role(user_id: int) -> str:
    """Return the role for a given user ID."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row["role"] if row else "user"


def set_user_role(user_id: int, role: str) -> None:
    """Update the role of a user."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()


def delete_user(user_id: int) -> None:
    """Delete a user and associated email accounts and logs."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_all_users() -> List[sqlite3.Row]:
    """Return a list of all users."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY username")
    rows = cur.fetchall()
    conn.close()
    return rows


def add_email_account(
    user_id: int,
    email_address: str,
    imap_server: str,
    imap_port: int,
    smtp_server: str,
    smtp_port: int,
    username: str,
    password: str,
) -> None:
    """Store email account details for a user.

    If an account already exists for the user, it is replaced.
    """
    encrypted = encrypt_password(password)
    conn = get_db_connection()
    cur = conn.cursor()
    # Check if existing account
    cur.execute("SELECT id FROM email_accounts WHERE user_id = ?", (user_id,))
    existing = cur.fetchone()
    if existing:
        cur.execute(
            """
            UPDATE email_accounts
            SET email_address=?, imap_server=?, imap_port=?, smtp_server=?, smtp_port=?, username=?, encrypted_password=?
            WHERE user_id=?
            """,
            (email_address, imap_server, imap_port, smtp_server, smtp_port, username, encrypted, user_id),
        )
    else:
        cur.execute(
            """
            INSERT INTO email_accounts (user_id, email_address, imap_server, imap_port, smtp_server, smtp_port, username, encrypted_password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, email_address, imap_server, imap_port, smtp_server, smtp_port, username, encrypted),
        )
    conn.commit()
    conn.close()


def get_email_account(user_id: int) -> Optional[Dict[str, Any]]:
    """Return the email account configuration for a user."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM email_accounts WHERE user_id = ?
        """,
        (user_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "email_address": row["email_address"],
        "imap_server": row["imap_server"],
        "imap_port": row["imap_port"],
        "smtp_server": row["smtp_server"],
        "smtp_port": row["smtp_port"],
        "username": row["username"],
        "password": decrypt_password(row["encrypted_password"]),
    }


def add_log(user_id: int, action: str) -> None:
    """Insert an entry into the logs for a user."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (user_id, timestamp, action) VALUES (?, ?, ?)",
        (user_id, datetime.utcnow().isoformat() + "Z", action),
    )
    conn.commit()
    conn.close()


def get_logs(user_id: Optional[int] = None, limit: int = 50) -> List[sqlite3.Row]:
    """Return recent logs.

    If `user_id` is provided, only logs for that user are returned.
    Otherwise, logs from all users are returned.  Results are ordered
    by timestamp descending and limited to `limit` entries.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    if user_id is not None:
        cur.execute(
            """
            SELECT logs.id, logs.timestamp, logs.action, users.username
            FROM logs JOIN users ON logs.user_id = users.id
            WHERE logs.user_id = ?
            ORDER BY logs.id DESC
            LIMIT ?
            """,
            (user_id, limit),
        )
    else:
        cur.execute(
            """
            SELECT logs.id, logs.timestamp, logs.action, users.username
            FROM logs JOIN users ON logs.user_id = users.id
            ORDER BY logs.id DESC
            LIMIT ?
            """,
            (limit,),
        )
    rows = cur.fetchall()
    conn.close()
    return rows