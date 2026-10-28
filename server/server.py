
import asyncio
import json

from database import uwierzytelnij

HOST = "0.0.0.0"
PORT = 8765
MAX_MESSAGE_LENGTH = 2000

# writer -> dane zalogowanego użytkownika
clients: dict[asyncio.StreamWriter, dict] = {}


async def send_json(writer, data):
    """Wysyła jeden komunikat JSON zakończony nową linią."""
    writer.write(
        (json.dumps(data, ensure_ascii=False) + "\n").encode("utf-8")
    )
    await writer.drain()


async def broadcast(data, exclude=None):
    """Wysyła komunikat do wszystkich zalogowanych klientów."""
    for writer in list(clients):
        if writer is exclude:
            continue

        try:
            await send_json(writer, data)
        except (ConnectionError, OSError):
            pass


async def handle_client(reader, writer):
    address = writer.get_extra_info("peername")
    login = None
    zalogowany = False

    try:
        # Logowanie: zachowujemy dotychczasowy protokół.
        writer.write(b"PODAJ_LOGIN\n")
        await writer.drain()

        data = await reader.readline()
        if not data:
            return

        login = data.decode("utf-8", errors="replace").strip()

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
            "utf-8", errors="replace"
        ).rstrip("\r\n")

        if not haslo or len(haslo) > 1024:
            writer.write(
                b"BLAD: Nieprawidlowy login lub haslo.\n"
            )
            await writer.drain()
            return

        poprawne_dane = await asyncio.to_thread(
            uwierzytelnij, login, haslo
        )
        del haslo

        if not poprawne_dane:
            writer.write(
                b"BLAD: Nieprawidlowy login lub haslo.\n"
            )
            await writer.drain()
            print(f"[LOGOWANIE] Nieudana próba z {address}")
            return

        if any(
            dane["login"].casefold() == login.casefold()
            for dane in clients.values()
        ):
            writer.write(
                b"BLAD: To konto jest juz zalogowane.\n"
            )
            await writer.drain()
            return

        clients[writer] = {
            "login": login,
            "ip": address[0],
            "p2p_port": None,
        }
        zalogowany = True

        writer.write(
            f"OK: Zalogowano jako {login}\n".encode("utf-8")
        )
        await writer.drain()

        print(f"[+] Zalogowano: {login} ({address})")

        await broadcast({
            "type": "system",
            "message": f"{login} dołączył do czatu.",
        })

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

            # Rejestracja portu nasłuchującego P2P.
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

            # Lista zalogowanych użytkowników.
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

            # Wyszukiwanie adresu wybranego użytkownika.
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

            # Domyślny tryb: broadcast.
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

    except (ConnectionError, OSError) as error:
        print(f"[!] Błąd połączenia {address}: {error}")

    finally:
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


async def main():
    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
        limit=8192,
    )

    print(f"Serwer działa na {HOST}:{PORT}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nSerwer zatrzymany.")
