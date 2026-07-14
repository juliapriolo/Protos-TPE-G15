#!/usr/bin/env python3
"""Prueba de estres del proxy SOCKS5 (TPE Protos - Grupo 15).

Abre N conexiones SOCKS5 concurrentes contra el servidor bajo prueba, hace el
handshake sin autenticacion (RFC1928) y un CONNECT hacia un destino de eco
(ver stress_echo_server.py), y mide:

  - cuantas conexiones lograron completar el handshake + CONNECT;
  - cuantas fallaron al conectar o durante el intercambio de datos;
  - el throughput agregado (bytes de ida y vuelta / tiempo total del nivel);
  - la latencia de conexion (tiempo entre abrir el socket TCP y recibir la
    respuesta del CONNECT), promedio y percentil 95.

Se corre una vez por cada nivel de concurrencia indicado en --levels, de
menor a mayor, para poder observar en que punto empieza a degradarse el
servidor (o directamente a rechazar conexiones).

Requiere Python 3.8+ (solo libreria estandar, sin dependencias externas).

Uso tipico:
    # 1) levantar el destino de eco
    python3 stress_echo_server.py --port 9099 &

    # 2) levantar el servidor bajo prueba
    ./bin/server -l 127.0.0.1 -p 1090 -L 127.0.0.1 -P 8090 &

    # 3) correr la prueba
    python3 stress_test.py --socks-port 1090 --target-port 9099 \
        --levels 100,250,500,600,750,1000
"""
import argparse
import asyncio
import socket
import statistics
import struct
import time

SOCKS_VERSION = 0x05
METHOD_NO_AUTH = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
RSV = 0x00


class StageError(RuntimeError):
    """Error en una etapa puntual del handshake, para poder contarlas por separado."""


async def socks5_handshake_connect(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    timeout: float,
):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(socks_host, socks_port), timeout=timeout
    )

    # Greeting: VER | NMETHODS | METHODS
    writer.write(bytes([SOCKS_VERSION, 1, METHOD_NO_AUTH]))
    await writer.drain()
    greeting_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    if greeting_resp[0] != SOCKS_VERSION or greeting_resp[1] != METHOD_NO_AUTH:
        raise StageError(f"greeting rechazado: {greeting_resp.hex()}")

    # Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT (destino IPv4 fijo)
    addr_bytes = socket.inet_aton(target_host)
    request = (
        bytes([SOCKS_VERSION, CMD_CONNECT, RSV, ATYP_IPV4])
        + addr_bytes
        + struct.pack("!H", target_port)
    )
    writer.write(request)
    await writer.drain()

    header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    _ver, rep, _rsv, atyp = header
    if rep != 0x00:
        raise StageError(f"CONNECT fallo, REP=0x{rep:02x}")

    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)
    elif atyp == 0x03:
        domain_len = (await reader.readexactly(1))[0]
        await reader.readexactly(domain_len + 2)
    else:
        raise StageError(f"ATYP desconocido en respuesta: {atyp}")

    return reader, writer


async def worker(
    worker_id: int,
    args: argparse.Namespace,
    counters: dict,
    connect_latencies: list,
) -> None:
    if args.stagger > 0:
        await asyncio.sleep(worker_id * args.stagger)

    payload = bytes([worker_id % 256]) * args.payload
    t_start = time.perf_counter()

    try:
        reader, writer = await socks5_handshake_connect(
            args.socks_host, args.socks_port, args.target_host, args.target_port, args.timeout
        )
    except Exception:
        counters["connect_fail"] += 1
        return

    connect_latencies.append(time.perf_counter() - t_start)
    counters["connected_now"] += 1
    counters["connected_peak"] = max(counters["connected_peak"], counters["connected_now"])

    if args.hold_deadline is not None:
        remaining = args.hold_deadline - time.perf_counter()
        if remaining > 0:
            await asyncio.sleep(remaining)

    try:
        for _ in range(args.rounds):
            writer.write(payload)
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(args.payload), timeout=args.timeout)
            if echoed != payload:
                raise StageError("eco corrupto")
            counters["bytes_total"] += 2 * args.payload  # ida + vuelta
        counters["ok"] += 1
    except Exception:
        counters["transfer_fail"] += 1
    finally:
        counters["connected_now"] -= 1
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def run_level(n: int, args: argparse.Namespace) -> dict:
    counters = {
        "ok": 0,
        "connect_fail": 0,
        "transfer_fail": 0,
        "bytes_total": 0,
        "connected_now": 0,
        "connected_peak": 0,
    }
    connect_latencies: list = []

    t0 = time.perf_counter()
    # deadline compartido: todas las conexiones que lograron conectar esperan
    # hasta este instante antes de empezar a transferir, para garantizar que
    # coincidan abiertas al mismo tiempo aunque el intento de conexion se haya
    # escalonado con --stagger (evita medir el backlog de listen() en vez de
    # la concurrencia sostenida real).
    args.hold_deadline = t0 + (n * args.stagger) + args.hold if args.hold > 0 else None

    tasks = [
        asyncio.create_task(worker(i, args, counters, connect_latencies)) for i in range(n)
    ]
    await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = time.perf_counter() - t0

    throughput_mib_s = (counters["bytes_total"] / elapsed / (1024 * 1024)) if elapsed > 0 else 0.0
    if connect_latencies:
        avg_connect_ms = statistics.mean(connect_latencies) * 1000
        sorted_lat = sorted(connect_latencies)
        p95_idx = min(len(sorted_lat) - 1, int(len(sorted_lat) * 0.95))
        p95_connect_ms = sorted_lat[p95_idx] * 1000
    else:
        avg_connect_ms = float("nan")
        p95_connect_ms = float("nan")

    print(
        f"N={n:5d} | ok={counters['ok']:5d} | connect_fail={counters['connect_fail']:5d} | "
        f"transfer_fail={counters['transfer_fail']:5d} | peak_concurrentes={counters['connected_peak']:5d} | "
        f"tiempo={elapsed:6.2f}s | throughput={throughput_mib_s:8.2f} MiB/s | "
        f"connect_avg={avg_connect_ms:7.1f}ms | connect_p95={p95_connect_ms:7.1f}ms"
    )

    return {"n": n, "elapsed": elapsed, "throughput_mib_s": throughput_mib_s, **counters}


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--socks-host", default="127.0.0.1")
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--levels", default="50,100,250,500,600,750,1000")
    parser.add_argument("--payload", type=int, default=4096, help="bytes por ronda de eco")
    parser.add_argument("--rounds", type=int, default=5, help="rondas de eco por conexion")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--stagger",
        type=float,
        default=0.0,
        help="segundos de espera entre el intento de conexion de un worker y el siguiente, "
        "para distinguir saturacion del backlog de listen() de un limite sostenido real",
    )
    parser.add_argument(
        "--hold",
        type=float,
        default=0.0,
        help="si es > 0, todas las conexiones exitosas esperan hasta este tiempo (en segundos, "
        "contado desde el inicio del nivel mas el escalonamiento) antes de transferir datos, "
        "para forzar que coincidan abiertas simultaneamente",
    )
    args = parser.parse_args()

    levels = [int(x) for x in args.levels.split(",")]

    header = (
        f"{'nivel':>5} | {'ok':>5} | {'con_fail':>8} | {'xfer_fail':>9} | "
        f"{'tiempo':>7} | {'throughput':>12} | {'lat_avg':>8} | {'lat_p95':>8}"
    )
    print(f"Prueba de estres SOCKS5 -> {args.socks_host}:{args.socks_port} "
          f"(destino eco {args.target_host}:{args.target_port})")
    print(f"payload={args.payload}B rounds={args.rounds} timeout={args.timeout}s")
    print("-" * len(header))

    results = []
    for n in levels:
        results.append(await run_level(n, args))

    print("-" * len(header))
    print("Resumen: primer nivel con al menos una falla de conexion:")
    for r in results:
        if r["connect_fail"] > 0 or r["transfer_fail"] > 0:
            print(f"  N={r['n']} -> connect_fail={r['connect_fail']} transfer_fail={r['transfer_fail']}")
            break
    else:
        print("  ningun nivel probado presento fallas")


if __name__ == "__main__":
    asyncio.run(main())
