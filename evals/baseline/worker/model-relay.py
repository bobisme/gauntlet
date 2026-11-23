#!/usr/bin/env python3
"""Referee-owned CONNECT tunnel: worker -> one pinned model API host only.

The relay never reads provider credentials. The Pi process inside the worker
performs its own TLS through this raw byte tunnel, so the credential stays in
the worker's read-only auth mount and the host relay is a dumb pipe.
"""
import asyncio
import sys

ALLOW_HOST = "api.orcarouter.ai"
ALLOW_PORT = 443


async def handle(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        line = head.split(b"\r\n", 1)[0].decode("latin1")
        parts = line.split()
        if len(parts) != 3 or parts[0] != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await writer.drain()
            return
        host, _, port = parts[1].rpartition(":")
        if (host, port) != (ALLOW_HOST, str(ALLOW_PORT)):
            writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            await writer.drain()
            return
        remote_reader, remote_writer = await asyncio.open_connection(ALLOW_HOST, ALLOW_PORT)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def copy(source, destination):
            try:
                while chunk := await source.read(65536):
                    destination.write(chunk)
                    await destination.drain()
            except (OSError, ConnectionError):
                pass
            finally:
                try:
                    destination.close()
                except Exception:
                    pass

        await asyncio.gather(copy(reader, remote_writer), copy(remote_reader, writer))
    except (asyncio.TimeoutError, OSError, ValueError, ConnectionError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main(path):
    server = await asyncio.start_unix_server(handle, path=path)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
