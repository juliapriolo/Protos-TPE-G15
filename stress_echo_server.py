#!/usr/bin/env python3
"""Servidor TCP de eco usado como destino en la prueba de estres del proxy SOCKS5.

No forma parte del servidor SOCKS5 en si: es solo el "sitio remoto" al que el
proxy establece conexiones salientes durante la prueba de stress_test.py.
Cada byte que recibe lo devuelve tal cual, para que el cliente de la prueba
pueda medir throughput de ida y vuelta.

Uso:
    python3 stress_echo_server.py --host 127.0.0.1 --port 9099
"""
import argparse
import asyncio


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9099)
    args = parser.parse_args()

    server = await asyncio.start_server(handle_client, args.host, args.port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"echo server escuchando en {sockets}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
