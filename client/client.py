
import asyncio
import json
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout


import ssl
import base64
import hashlib
import hmac

HOST = "127.0.0.1"
AUTH_PORT = 8889
CHAT_PORT = 8888

MAX_MESSAGE_LENGTH = 2000


async def send_json(writer, data):
    writer.write(
        (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")
    )
    await writer.drain()


async def read_json(reader):
    data = await reader.readline()

    if not data:
        return None

    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


class ClientState:
    def __init__(self):
        self.mode = "broadcast"
        self.peer_writer = None
        self.peer_login = None
        self.peer_task = None
        self.pending_connect = None


# Close current private chat.
async def close_peer(state):
    """Close current private chat."""

    writer = state.peer_writer
    task = state.peer_task

    state.peer_writer = None
    state.peer_login = None
    state.peer_task = None
    state.mode = "broadcast"

    if writer is not None:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass

    current = asyncio.current_task()

    if task is not None and task is not current and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


# Receiving messages.
async def peer_receiver(reader, writer, state):
    """Receiving messages."""
    try:
        while True:
            data = await read_json(reader)

            if data is None:
                print("\n[P2P] Połączenie prywatne zostało zamknięte.")
                break

            kind = data.get("type")

            if kind == "private_message":
                login = data.get("login", state.peer_login or "Użytkownik")
                message = data.get("message", "")
                print(f"[P2P] {login}: {message}")

            elif kind == "peer_closed":
                print("\n[P2P] Rozmówca zakończył połączenie.")
                break

    except asyncio.CancelledError:
        raise
    except (ConnectionError, OSError) as error:
        print(f"\n[P2P] Błąd połączenia: {error}")

    finally:
        if state.peer_writer is writer:
            state.peer_writer = None
            state.peer_login = None
            state.peer_task = None
            state.mode = "broadcast"
            print("\n[INFO] Powrót do broadcastu.")


# Handle connection form another user.
async def handle_peer(reader, writer, state, login):
    """Handle connection form another user"""
    try:
        hello = await asyncio.wait_for(
            read_json(reader),
            timeout=10,
        )

        if not hello or hello.get("type") != "peer_hello":
            writer.close()
            await writer.wait_closed()
            return

        remote_login = hello.get("login", "Użytkownik")

        if not isinstance(remote_login, str) or not remote_login:
            writer.close()
            await writer.wait_closed()
            return

        # Only one active connection at once
        if state.peer_writer is not None:
            await send_json(writer, {
                "type": "peer_rejected",
                "message": "Użytkownik prowadzi już rozmowę prywatną.",
            })
            writer.close()
            await writer.wait_closed()
            return

        await send_json(writer, {
            "type": "peer_hello_ok",
            "login": login,
        })

        state.peer_writer = writer
        state.peer_login = remote_login
        state.mode = "private"

        print(f"\n[P2P] Połączono bezpośrednio z użytkownikiem: {remote_login}")

        state.peer_task = asyncio.current_task()
        await peer_receiver(reader, writer, state)

    except asyncio.TimeoutError:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    except (ConnectionError, OSError) as error:
        print(f"\n[P2P] Błąd połączenia przychodzącego: {error}")


# Establishing a direct connection to another user.
async def connect_peer(ip, port, remote_login, state, login):
    """Establishing a direct connection to another user."""
    reader = None
    writer = None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, limit=8192),
            timeout=10,
        )

        await send_json(writer, {
            "type": "peer_hello",
            "login": login,
        })

        response = await asyncio.wait_for(
            read_json(reader),
            timeout=10,
        )

        if not response or response.get("type") != "peer_hello_ok":
            reason = (
                response.get("message", "Połączenie odrzucone.")
                if response else "Brak odpowiedzi od rozmówcy."
            )
            print(f"[P2P] {reason}")
            writer.close()
            await writer.wait_closed()
            return False

        if state.peer_writer is not None:
            writer.close()
            await writer.wait_closed()
            print("\n[P2P] Masz już aktywne połączenie prywatne.")
            return False

        state.peer_writer = writer
        state.peer_login = response.get("login", remote_login)
        state.mode = "private"

        state.peer_task = asyncio.create_task(
            peer_receiver(reader, writer, state)
        )

        print(f"\n[P2P] Połączono bezpośrednio z: {state.peer_login}")
        print("[INFO] Wiadomości są teraz prywatne.")
        return True

    except (OSError, asyncio.TimeoutError, ConnectionError) as error:
        print(f"\n[P2P] Nie udało się połączyć z {remote_login}: {error}")

        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

        return False


# Received broadcast and server information.
async def receive_server(reader, writer, state, login):
    """Received broadcast and server information."""
    try:
        while True:
            data = await read_json(reader)

            if data is None:
                print("[INFO] Serwer zamknął połączenie.")
                return

            kind = data.get("type")

            if kind == "system":
                print(f"[SERVER] {data.get('message', '')}")

            elif kind == "chat":
                print(
                    f"[{data.get('login', 'Użytkownik')}] "
                    f"{data.get('message', '')}"
                )

            elif kind == "error":
                print(f"[SERVER] {data.get('message', '')}")

            elif kind == "p2p_registered":
                print(
                    f"[P2P] Port nasłuchujący: {data.get('port')}"
                )

            elif kind == "users":
                users = data.get("users", [])
                print("\n--- Użytkownicy online ---")

                if not users:
                    print("Brak innych zalogowanych użytkowników.")

                for user in users:
                    status = (
                        "P2P dostępne"
                        if user.get("p2p_port")
                        else "P2P niedostępne"
                    )
                    print(f"- {user.get('login')} ({status})")

                print("--------------------------")

            elif kind == "connect_result":
                future = state.pending_connect

                if not data.get("ok"):
                    print(f"[P2P] {data.get('message', 'Błąd połączenia.')}")

                    if future is not None and not future.done():
                        future.set_result(False)
                    continue

                if future is None or future.done():
                    continue

                success = await connect_peer(
                    data["ip"],
                    data["port"],
                    data["login"],
                    state,
                    login,
                )

                if not future.done():
                    future.set_result(success)

    except asyncio.CancelledError:
        raise
    except (ConnectionError, OSError) as error:
        print(f"[INFO] Utracono połączenie z serwerem: {error}")


# User commend handler and sending messages.
async def send_messages(writer, session, state, login):
    """User commend handler and sending messages."""
    while True:
        try:
            with patch_stdout():
                message = await session.prompt_async("> ", is_password = False)

        except (EOFError, KeyboardInterrupt):
            return

        message = message.strip()

        if not message:
            continue

        if message == "/quit":
            return

        if message == "/users":
            await send_json(writer, {"type": "users"})
            continue

        if message.startswith("/connect "):
            target = message[len("/connect "):].strip()

            if not target:
                print("[INFO] Użycie: /connect login")
                continue

            if state.peer_writer is not None:
                print("[INFO] Najpierw zakończ obecną rozmowę komendą /back.")
                continue

            if state.pending_connect is not None:
                print("[INFO] Trwa już próba połączenia.")
                continue

            future = asyncio.get_running_loop().create_future()
            state.pending_connect = future

            try:
                await send_json(writer, {
                    "type": "connect",
                    "login": target,
                })

                try:
                    await asyncio.wait_for(future, timeout=15)
                except asyncio.TimeoutError:
                    print("[P2P] Przekroczono czas oczekiwania na połączenie.")

            finally:
                state.pending_connect = None

            continue

        if message == "/back":
            if state.peer_writer is None:
                print("[INFO] Nie prowadzisz rozmowy prywatnej.")
                continue

            try:
                await send_json(state.peer_writer, {
                    "type": "peer_closed",
                })
            except (ConnectionError, OSError):
                pass

            await close_peer(state)
            print("[INFO] Powrót do broadcastu.")
            continue

        if message.startswith("/"):
            print(
                "[INFO] Nieznana komenda. Dostępne: "
                "/users, /connect login, /back, /quit"
            )
            continue

        if len(message) > MAX_MESSAGE_LENGTH:
            print("[INFO] Wiadomość może mieć maksymalnie 2000 znaków.")
            continue

        if state.mode == "private" and state.peer_writer is not None:
            try:
                await send_json(state.peer_writer, {
                    "type": "private_message",
                    "login": login,
                    "message": message,
                })
            except (ConnectionError, OSError):
                print("[P2P] Nie udało się wysłać wiadomości.")
                await close_peer(state)

        else:
            try:
                await send_json(writer, {
                    "type": "broadcast",
                    "message": message,
                })
            except (ConnectionError, OSError):
                print("[INFO] Nie udało się wysłać wiadomości.")
                return

# Create ssl context to make connection.
def create_ssl_context():
    """Create ssl context to make connection"""
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile="server.crt"
    )

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    return context

# TLS Login and verification
async def login_user(reader, writer, session):
    """Authenticate the user over TLS.
    Returns:
        login: The authenticated user's login.
        token: The session token issued by the server.
        session_secret: The secret used for HMAC-based authentication
            when establishing the chat connection over TCP.
"""

    response = await reader.readline()
    
    if not response:
        print("[INFO] Serwer zamknął połączenie.")
        return None

    print(response.decode("utf-8", errors="replace").strip())

    with patch_stdout():
        login = (await session.prompt_async("Login: ")).strip()

    writer.write((login + "\n").encode("utf-8"))
    await writer.drain()

    # Password

    response = await reader.readline()

    if not response:
        print("[INFO] Serwer zamknął połączenie.")
        return None

    response_text = response.decode(
        "utf-8", errors="replace"
    ).strip()

    if response_text != "PODAJ_HASLO":
        print(response_text)
        return None

    with patch_stdout():
        password = await session.prompt_async(
            "Hasło: ",
            is_password=True,
        )

    writer.write((password + "\n").encode("utf-8"))
    await writer.drain()

    del password

    # Login result

    response = await reader.readline()

    if not response:
        print("[INFO] Serwer zamknął połączenie.")
        return None

    response_text = response.decode(
        "utf-8", errors="replace"
    ).strip()

    print(response_text)

    if not response_text.startswith("OK:"):
        return None

    # Receiving token

    token_data = await reader.readline()

    if not token_data:
        print("[TLS] Nie otrzymano tokenu.")
        return None

    token = token_data.decode("utf-8").strip()

    # Receiving secret

    secret_data = await reader.readline()

    if not secret_data:
        print("[TLS] Nie otrzymano sekretu sesji.")
        return None

    session_secret = base64.b64decode(
        secret_data.strip(),
        validate=True,
    )

    # Check if session secret isnt null
    if not session_secret:
        print("[TLS] Otrzymano pusty sekret sesji.")
        return None

    print("[TLS] Uwierzytelnianie zakończone.")

    # Closing connection TLS

    writer.close()
    await writer.wait_closed()
    writer = None
    return login, token, session_secret

async def chat_connection(reader, writer, token, session_secret):
    # Send token
    
    writer.write((token + "\n").encode("utf-8"))
    await writer.drain()

    # Receiving server info

    nonce_data = await reader.readline()

    if not nonce_data:
        print("[CHAT] Serwer nie wysłał wyzwania.")
        return False

    nonce_text = nonce_data.decode("ascii").strip()

    if nonce_text == "AUTH_ERROR":
        print("[CHAT] Serwer odrzucił sesję.")
        return False

    try:
        nonce = bytes.fromhex(nonce_text)
    except ValueError:
        print("[CHAT] Nieprawidłowe wyzwanie serwera.")
        return False
    # Calculation HMAC

    proof = hmac.new(
        session_secret,
        nonce,
        hashlib.sha256,
    ).hexdigest()

    writer.write((proof + "\n").encode("ascii"))
    await writer.drain()

    

    # Confirmation of entry into the messenger
    response = await reader.readline()

    if not response:
        print("[CHAT] Serwer zamknął połączenie.")
        return False

    response_text = response.decode(
        "utf-8", errors="replace"
    ).strip()

    if response_text != "CHAT_OK":
        print(f"[CHAT] Błąd uwierzytelniania: {response_text}")
        return False

    print("[CHAT] Zalogowano do komunikatora!")
    return True

async def main():

    ssl_context = create_ssl_context()

    session = PromptSession()
    state = ClientState()

    login = None
    auth_writer = None
    writer = None
    reader = None

    p2p_server = None
    receiver = None
    sender = None

    try:
        # ======================================
        # 1. Connect TLS - PORT 8889
        # ======================================

        print("[TLS] Łączenie z serwerem logowania...")

        auth_reader, auth_writer = await asyncio.open_connection(
            HOST,
            AUTH_PORT,
            limit=8192,
            ssl=ssl_context,
            server_hostname="localhost",
        )

        print("[TLS] Połączono.")

        # Login via TLS
        
        auth_result = await login_user(auth_reader, auth_writer, session)

        # Return if some error is in the authorization tls
        if auth_result is None:
            return

        login, token, session_secret = auth_result

        # ======================================
        # 2. NEW CONNECTION TCP - PORT 8888
        # ======================================

        print("[CHAT] Łączenie z komunikatorem...")

        reader, writer = await asyncio.open_connection(
            HOST,
            CHAT_PORT,
            limit=8192,
        )

        print("[CHAT] Połączono z portem komunikatora.")

        # Return if some error is in the tcp connection
        if not await chat_connection(reader, writer, token, session_secret):
            return
        del session_secret
        # ======================================
        # 3. START P2P
        # ======================================

        p2p_server = await asyncio.start_server(
            lambda r, w: handle_peer(r, w, state, login),
            "0.0.0.0",
            0,
            limit=8192,
        )

        p2p_port = p2p_server.sockets[0].getsockname()[1]

        await send_json(writer, {
            "type": "register_p2p",
            "port": p2p_port,
        })

        print("\nDomyślny tryb: BROADCAST")
        print("Komendy: /users, /connect login, /back, /quit")
        print("Aby pisać prywatnie, połącz się przez /connect login.")
        print("-" * 50)

        # ======================================
        # 4. RECEIVING AND SEND
        # ======================================

        receiver = asyncio.create_task(
            receive_server(reader, writer, state, login)
        )

        sender = asyncio.create_task(
            send_messages(writer, session, state, login)
        )

        done, pending = await asyncio.wait(
            {receiver, sender},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in done:
            if not task.cancelled():
                error = task.exception()

                if error:
                    print(f"[INFO] Błąd klienta: {error}")

    except (ConnectionError, OSError, asyncio.TimeoutError) as error:
        print(f"[INFO] Błąd połączenia: {error}")

    except (ValueError, base64.binascii.Error) as error:
        print(f"[INFO] Błąd danych sesji: {error}")

    finally:

        for task in (sender, receiver):
            if task is not None and not task.done():
                task.cancel()

        await asyncio.gather(
            *(task for task in (sender, receiver) if task is not None),
            return_exceptions=True,
        )

        await close_peer(state)

        if p2p_server is not None:
            p2p_server.close()
            await p2p_server.wait_closed()

        for connection in (auth_writer, writer):
            if connection is not None:
                connection.close()

                try:
                    await connection.wait_closed()
                except (ConnectionError, OSError):
                    pass

        print("[INFO] Klient został zamknięty.")



if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nZamykanie klienta.")
