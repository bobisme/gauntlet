#!/usr/bin/env python3
"""Offline qualification stand-in for the worker's loopback forwarder."""

import os
from pathlib import Path
import selectors
import socket
import threading


READY = Path("/runtime/forwarder.ready")


def copy(source, destination):
    try:
        while chunk := source.recv(65536):
            destination.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def bridge(client, upstream_path):
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(upstream_path)
    except OSError:
        client.close()
        upstream.close()
        return
    left = threading.Thread(target=copy, args=(client, upstream))
    right = threading.Thread(target=copy, args=(upstream, client))
    left.start()
    right.start()
    left.join()
    right.join()
    client.close()
    upstream.close()


def main():
    routes = [(18080, "/gateway/model.sock")]
    proxy_text = os.environ.get("M0_PROXY_PORT")
    if proxy_text is not None:
        if not proxy_text.isdecimal() or not 1 <= int(proxy_text) <= 65535:
            raise SystemExit("invalid M0_PROXY_PORT")
        routes.insert(0, (int(proxy_text), "/gateway/proxy.sock"))
    selector = selectors.DefaultSelector()
    listeners = []
    for port, upstream_path in routes:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(4)
        listener.setblocking(False)
        selector.register(listener, selectors.EVENT_READ, upstream_path)
        listeners.append(listener)
    READY.write_text(f"{os.getpid()}\n", encoding="ascii")
    while True:
        for key, _events in selector.select():
            client, _address = key.fileobj.accept()
            threading.Thread(target=bridge, args=(client, key.data), daemon=True).start()


if __name__ == "__main__":
    main()
