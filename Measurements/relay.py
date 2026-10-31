#!/usr/bin/env python3
"""
relay.py - loopback TCP relay that records every chunk (time, direction, bytes).

Placed between `openssl s_client` and `openssl s_server`, it measures the
application-layer (TLS record) bytes of each flight without packet capture
privileges. One JSON line per connection is appended to --log:
    {"chunks": [[t_ms, dir, nbytes], ...]}   dir 0 = client->server, 1 = server->client
"""
import argparse
import asyncio
import json
import time


async def pipe(reader, writer, direction, chunks, t0):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            chunks.append([round((time.perf_counter() - t0) * 1e3, 4), direction, len(data)])
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(c_reader, c_writer, args):
    t0 = time.perf_counter()
    s_reader, s_writer = await asyncio.open_connection("127.0.0.1", args.upstream)
    chunks = []
    await asyncio.gather(pipe(c_reader, s_writer, 0, chunks, t0), pipe(s_reader, c_writer, 1, chunks, t0))
    with open(args.log, "a") as fh:
        fh.write(json.dumps({"chunks": chunks}) + "\n")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--upstream", type=int, required=True)
    ap.add_argument("--log", required=True)
    args = ap.parse_args()
    server = await asyncio.start_server(lambda r, w: handle(r, w, args), "127.0.0.1", args.listen)
    print("READY", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
