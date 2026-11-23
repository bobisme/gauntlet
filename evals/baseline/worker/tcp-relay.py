#!/usr/bin/env python3
"""Referee-owned TCP relay: one fixed worker loopback port -> one host service.

Used for the pinned Teapot proxy listener. The relay forwards raw bytes and
reads no credential or target state.
"""
import asyncio
import sys


async def relay(reader, writer, port):
    try:
        remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", port)

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
    except (OSError, ConnectionError):
        try:
            writer.close()
        except Exception:
            pass


async def main(path, port):
    server = await asyncio.start_unix_server(lambda r, w: relay(r, w, port), path=path)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], int(sys.argv[2])))
