
import sqlite3
import hashlib
import hmac
from pathlib import Path

DB_NAME = Path(__file__).with_name("users.db")


def hash_hasla(haslo: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        haslo.encode("utf-8"),
        bytes.fromhex(salt),
        600_000,
    ).hex()


def uwierzytelnij(login: str, haslo: str) -> bool:
    try:
        with sqlite3.connect(DB_NAME) as conn:
            user = conn.execute(
                """
                SELECT salt, password_hash
                FROM users
                WHERE username = ?
                """,
                (login,),
            ).fetchone()

    except sqlite3.Error as error:
        print(f"[BAZA] Błąd SQLite: {error}")
        return False

    if user is None:
        return False

    salt, zapisany_hash = user

    try:
        podany_hash = hash_hasla(haslo, salt)
    except (ValueError, TypeError):
        return False

    return hmac.compare_digest(
        podany_hash,
        zapisany_hash,
    )
