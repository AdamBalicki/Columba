
import asyncio
import json
import ssl
import secrets
import hashlib
import hmac
import time
import base64

from database import uwierzytelnij


HOST = "0.0.0.0"
AUTH_PORT = 8889
CHAT_PORT = 8888

MAX_MESSAGE_LENGTH = 2000

# Oczekujące sesje po poprawnym logowaniu
pending_sessions = {}

# writer -> dane zalogowanego użytkownika
clients: dict[asyncio.StreamWriter, dict] = {}


# ==========================================
# TLS
# ==========================================

def create_ssl_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    context.load_cert_chain(
        certfile="server.crt",
        keyfile="server.key"
    )

    return context


# ==========================================
# FUNKCJE POMOCNICZE
# ==========================================

async def send_json(writer, data):
    writer.write(
        (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")
    )
    await writer.drain()


async def broadcast(data, exclude=None):

    for writer in list(clients):
        if writer is exclude:
            continue

        try:
            await send_json(writer, data)
        except (ConnectionError, OSError):
            pass


def clean_expired_sessions():
    now = time.monotonic()

    expired = [
        token
        for token, session in pending_sessions.items()
        if session["expires"] < now
    ]

    for token in expired:
        pending_sessions.pop(token, None)


def login_is_active(login):
    return any(
        dane["login"].casefold() == login.casefold()
        for dane in clients.values()
    ) or any(
        session["login"].casefold() == login.casefold()
        and session["expires"] >= time.monotonic()
        for session in pending_sessions.values()
    )


# ==========================================
# 1. LOGOWANIE TLS
# ==========================================

async def handle_auth_client(reader, writer):

    address = writer.get_extra_info("peername")

    try:

        writer.write(b"PODAJ_LOGIN\n")
        await writer.drain()

        data = await reader.readline()

        if not data:
            return

        login = data.decode(
            "utf-8",
            errors="replace"
        ).strip()

        if (
            not login
            or len(login) > 50
            or any(ord(c) < 32 for c in login)
        ):
            writer.write(b"BLAD: Nieprawidlowy login.\n")
            await writer.drain()
            return

        writer.write(b"PODAJ_HASLO\n")
        await writer.drain()

        data = await reader.readline()

        if not data:
            return

        haslo = data.decode(
            "utf-8",
            errors="replace"
        ).rstrip("\r\n")

        if not haslo or len(haslo) > 1024:
            writer.write(
                b"BLAD: Nieprawidlowy login lub haslo.\n"
            )
            await writer.drain()
            return

        poprawne_dane = await asyncio.to_thread(
            uwierzytelnij,
            login,
            haslo
        )

        del haslo

        if not poprawne_dane:
            writer.write(
                b"BLAD: Nieprawidlowy login lub haslo.\n"
            )
            await writer.drain()

            print(f"[LOGOWANIE] Nieudana próba z {address}")
            return

        clean_expired_sessions()

        if login_is_active(login):
            writer.write(
                b"BLAD: To konto jest juz zalogowane.\n"
            )
            await writer.drain()
            return

        # Generowanie jednorazowej sesji

        token = secrets.token_urlsafe(32)
        session_secret = secrets.token_bytes(32)

        pending_sessions[token] = {
            "login": login,
            "secret": session_secret,
            "expires": time.monotonic() + 60,
            "in_use": False,
        }

        # Potwierdzenie logowania

        writer.write(
            f"OK: Zalogowano jako {login}\n".encode("utf-8")
        )

        writer.write(
            f"{token}\n".encode("utf-8")
        )

        writer.write(
            base64.b64encode(session_secret) + b"\n"
        )

        await writer.drain()

        print(f"[+] Uwierzytelniono TLS: {login} ({address})")

    except (ConnectionError, OSError) as error:
        print(f"[!] Błąd logowania {address}: {error}")

    finally:
        writer.close()

        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


# ==========================================
# 2. KOMUNIKATOR TCP
# ==========================================

async def handle_chat_client(reader, writer):

    address = writer.get_extra_info("peername")

    login = None
    zalogowany = False
    token = None
    session = None

    try:

        # Pobranie tokenu sesji

        data = await asyncio.wait_for(
            reader.readline(),
            timeout=10
        )

        if not data:
            return

        token = data.decode("utf-8").strip()

        clean_expired_sessions()

        session = pending_sessions.get(token)

        if (
            not session
            or session["expires"] < time.monotonic()
            or session["in_use"]
        ):
            writer.write(b"AUTH_ERROR\n")
            await writer.drain()
            return

        session["in_use"] = True

        # Weryfikacja posiadania sekretu sesji

        nonce = secrets.token_bytes(32)

        writer.write(nonce.hex().encode("ascii") + b"\n")
        await writer.drain()

        proof_data = await asyncio.wait_for(
            reader.readline(),
            timeout=10
        )

        expected = hmac.new(
            session["secret"],
            nonce,
            hashlib.sha256
        ).hexdigest()

        received = proof_data.decode(
            "ascii",
            errors="ignore"
        ).strip()

        if not hmac.compare_digest(received, expected):
            writer.write(b"AUTH_ERROR\n")
            await writer.drain()
            return

        login = session["login"]

        # Sesja jest jednorazowa
        pending_sessions.pop(token, None)
        token = None
        session = None

        # Kontrola, czy użytkownik nie jest już zalogowany

        if login_is_active(login):
            writer.write(b"AUTH_ERROR\n")
            await writer.drain()
            return

        # Dodanie użytkownika do komunikatora

        clients[writer] = {
            "login": login,
            "ip": address[0],
            "p2p_port": None,
        }

        zalogowany = True

        writer.write(b"CHAT_OK\n")
        await writer.drain()

        print(f"[+] Zalogowano do czatu: {login} ({address})")

        await broadcast({
            "type": "system",
            "message": f"{login} dołączył do czatu.",
        })

        # ======================================
        # OBSŁUGA WIADOMOŚCI I KOMEND
        # ======================================

        while True:

            data = await reader.readline()

            if not data:
                break

            if len(data) > 8192:
                await send_json(writer, {
                    "type": "error",
                    "message": "Komunikat jest za duży.",
                })
                continue

            try:
                request = json.loads(data.decode("utf-8"))

            except (UnicodeDecodeError, json.JSONDecodeError):
                await send_json(writer, {
                    "type": "error",
                    "message": "Nieprawidłowy format komunikatu.",
                })
                continue

            if not isinstance(request, dict):
                continue

            command = request.get("type")

            # Rejestracja portu P2P

            if command == "register_p2p":

                port = request.get("port")

                if (
                    isinstance(port, int)
                    and not isinstance(port, bool)
                    and 1 <= port <= 65535
                ):
                    clients[writer]["p2p_port"] = port

                    await send_json(writer, {
                        "type": "p2p_registered",
                        "port": port,
                    })

                else:
                    await send_json(writer, {
                        "type": "error",
                        "message": "Nieprawidłowy port P2P.",
                    })

            # Lista użytkowników

            elif command == "users":

                users = [
                    {
                        "login": dane["login"],
                        "ip": dane["ip"],
                        "p2p_port": dane["p2p_port"],
                    }
                    for peer_writer, dane in clients.items()
                    if peer_writer is not writer
                ]

                await send_json(writer, {
                    "type": "users",
                    "users": users,
                })

            # Wyszukiwanie użytkownika P2P

            elif command == "connect":

                target = request.get("login", "")

                if not isinstance(target, str):
                    target = ""

                target_writer = next(
                    (
                        peer_writer
                        for peer_writer, dane in clients.items()
                        if dane["login"].casefold()
                        == target.casefold()
                    ),
                    None,
                )

                if target_writer is None:
                    await send_json(writer, {
                        "type": "connect_result",
                        "ok": False,
                        "message": "Użytkownik nie jest online.",
                    })
                    continue

                if target_writer is writer:
                    await send_json(writer, {
                        "type": "connect_result",
                        "ok": False,
                        "message": "Nie możesz połączyć się ze sobą.",
                    })
                    continue

                target_data = clients[target_writer]

                if not target_data["p2p_port"]:
                    await send_json(writer, {
                        "type": "connect_result",
                        "ok": False,
                        "message": "Użytkownik nie jest gotowy na P2P.",
                    })
                    continue

                await send_json(writer, {
                    "type": "connect_result",
                    "ok": True,
                    "login": target_data["login"],
                    "ip": target_data["ip"],
                    "port": target_data["p2p_port"],
                })

            # Broadcast

            elif command == "broadcast":

                message = request.get("message", "")

                if not isinstance(message, str):
                    continue

                message = message.strip()

                if not message:
                    continue

                if len(message) > MAX_MESSAGE_LENGTH:
                    await send_json(writer, {
                        "type": "error",
                        "message": "Wiadomość może mieć maksymalnie 2000 znaków.",
                    })
                    continue

                print(f"[BROADCAST] {login}: {message}")

                await broadcast({
                    "type": "chat",
                    "login": login,
                    "message": message,
                }, exclude=writer)

            else:
                await send_json(writer, {
                    "type": "error",
                    "message": "Nieznane polecenie serwera.",
                })

    except asyncio.TimeoutError:
        print(f"[INFO] Przekroczono czas uwierzytelniania: {address}")

    except (ConnectionError, OSError) as error:
        print(f"[!] Błąd połączenia {address}: {error}")

    finally:

        # Niewykorzystana lub przerwana sesja nie pozostaje aktywna
        if token is not None:
            pending_sessions.pop(token, None)

        clients.pop(writer, None)

        writer.close()

        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass

        if zalogowany:

            print(f"[-] Rozłączono: {login} ({address})")

            await broadcast({
                "type": "system",
                "message": f"{login} opuścił czat.",
            })


# ==========================================
# 3. URUCHAMIANIE SERWERÓW
# ==========================================

async def main():

    ssl_context = create_ssl_context()

    auth_server = await asyncio.start_server(
        handle_auth_client,
        HOST,
        AUTH_PORT,
        ssl=ssl_context,
        limit=8192,
    )

    chat_server = await asyncio.start_server(
        handle_chat_client,
        HOST,
        CHAT_PORT,
        limit=8192,
    )

    print(f"Serwer TLS działa na porcie {AUTH_PORT}")
    print(f"Serwer komunikatora działa na porcie {CHAT_PORT}")

    async with auth_server, chat_server:

        await asyncio.gather(
            auth_server.serve_forever(),
            chat_server.serve_forever(),
        )


if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("\nSerwer zatrzymany.")
