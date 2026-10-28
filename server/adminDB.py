import sqlite3
import hashlib
import secrets
import hmac
from pathlib import Path
from getpass import getpass

DB_NAME = Path(__file__).with_name("users.db")


def polacz():
    return sqlite3.connect(DB_NAME)


def baza_istnieje():
    return DB_NAME.exists()


def utworz_baze():
    if baza_istnieje():
        print("\nBaza juz istnieje.")
        odp = input("Czy chcesz sprawdzic/uzupelnic tabele? (t/n): ")
        if odp.lower() != "t":
            return

    with polacz() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

    print("Baza i tabela uzytkownikow sa gotowe.")


def hash_hasla(haslo, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        haslo.encode("utf-8"),
        bytes.fromhex(salt),
        600_000
    ).hex()


def dodaj_uzytkownika():
    if not baza_istnieje():
        print("\nBaza nie istnieje. Najpierw utworz baze.")
        return

    login = input("Podaj login: ").strip()

    if not login:
        print("Login nie moze byc pusty.")
        return

    haslo = getpass("Podaj haslo: ")
    if len(haslo) < 8:
        print("Haslo musi miec przynajmniej 8 znakow.")
        return

    powtorzenie = getpass("Powtorz haslo: ")
    if haslo != powtorzenie:
        print("Hasla nie sa takie same.")
        return

    salt = secrets.token_hex(16)
    password_hash = hash_hasla(haslo, salt)

    try:
        with polacz() as conn:
            conn.execute("""
                INSERT INTO users (username, salt, password_hash)
                VALUES (?, ?, ?)
            """, (login, salt, password_hash))

        print(f"Dodano uzytkownika: {login}")

    except sqlite3.IntegrityError:
        print("Uzytkownik o takim loginie juz istnieje.")


def wyswietl_uzytkownikow():
    if not baza_istnieje():
        print("\nBaza nie istnieje.")
        return

    with polacz() as conn:
        # Celowo nie pobieramy skrótów haseł ani soli.
        users = conn.execute("""
            SELECT id, username, created_at
            FROM users
            ORDER BY id
        """).fetchall()

    if not users:
        print("\nBaza nie zawiera uzytkownikow.")
        return

    print("\n--- UZYTKOWNICY ---")
    print(f"{'ID':<5} {'LOGIN':<25} {'DATA UTWORZENIA'}")
    print("-" * 55)

    for user_id, username, created_at in users:
        print(f"{user_id:<5} {username:<25} {created_at}")


def usun_uzytkownika():
    if not baza_istnieje():
        print("\nBaza nie istnieje.")
        return

    login = input("Podaj login do usuniecia: ").strip()

    potwierdzenie = input(
        f"Czy na pewno usunac konto '{login}'? (t/n): "
    )

    if potwierdzenie.lower() != "t":
        print("Anulowano.")
        return

    with polacz() as conn:
        cursor = conn.execute(
            "DELETE FROM users WHERE username = ?",
            (login,)
        )

    if cursor.rowcount:
        print("Uzytkownik zostal usuniety.")
    else:
        print("Nie znaleziono takiego uzytkownika.")


def zmien_haslo():
    if not baza_istnieje():
        print("\nBaza nie istnieje.")
        return

    login = input("Podaj login uzytkownika: ").strip()

    with polacz() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (login,)
        ).fetchone()

    if user is None:
        print("Nie znaleziono takiego uzytkownika.")
        return

    haslo = getpass("Podaj nowe haslo: ")
    if len(haslo) < 8:
        print("Haslo musi miec przynajmniej 8 znakow.")
        return

    powtorzenie = getpass("Powtorz nowe haslo: ")
    if haslo != powtorzenie:
        print("Hasla nie sa takie same.")
        return

    salt = secrets.token_hex(16)
    password_hash = hash_hasla(haslo, salt)

    with polacz() as conn:
        conn.execute("""
            UPDATE users
            SET salt = ?, password_hash = ?
            WHERE username = ?
        """, (salt, password_hash, login))

    print("Haslo zostalo zmienione.")


def sprawdz_baze():
    print(f"\nSciezka bazy: {DB_NAME}")

    if not baza_istnieje():
        print("Baza nie istnieje.")
        return

    try:
        with polacz() as conn:
            tabela = conn.execute("""
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name = 'users'
            """).fetchone()

            if tabela is None:
                print("Plik istnieje, ale brakuje tabeli users.")
                return

            liczba = conn.execute(
                "SELECT COUNT(*) FROM users"
            ).fetchone()[0]

        print("Baza dziala poprawnie.")
        print(f"Liczba uzytkownikow: {liczba}")

    except sqlite3.Error as e:
        print(f"Blad bazy danych: {e}")


def menu():
    while True:
        print("""
================================
     PANEL BAZY UZYTKOWNIKOW
================================

1. Utworz / przygotuj baze danych
2. Wyswietl wszystkich uzytkownikow
3. Dodaj nowego uzytkownika
4. Usun uzytkownika
5. Zmien haslo uzytkownika
6. Sprawdz baze danych
0. Wyjscie
""")

        wybor = input("Wybierz opcje: ").strip()

        if wybor == "1":
            utworz_baze()
        elif wybor == "2":
            wyswietl_uzytkownikow()
        elif wybor == "3":
            dodaj_uzytkownika()
        elif wybor == "4":
            usun_uzytkownika()
        elif wybor == "5":
            zmien_haslo()
        elif wybor == "6":
            sprawdz_baze()
        elif wybor == "0":
            print("Koniec programu.")
            break
        else:
            print("Nieprawidlowa opcja. Sprobuj ponownie.")


if __name__ == "__main__":
    menu()
