"""Shared HTTP client for the development fixture acceptance checks."""

import http.client
import json
from collections import namedtuple


Reply = namedtuple("Reply", ["status", "headers", "body"])


def request_http(authority, request, *, cookie=None, body=None, headers=()):
    conn = http.client.HTTPConnection(authority, timeout=5)
    method, path = request.split(" ", 1)
    try:
        conn.putrequest(method, path)
        for header, value in headers:
            conn.putheader(header, value)
        if cookie:
            conn.putheader("Cookie", cookie)
        if body is not None:
            body = json.dumps(body).encode()
            if not any(name.lower() == "content-type" for name, _ in headers):
                conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        response = conn.getresponse()
        return Reply(response.status, response.headers, response.read())
    finally:
        conn.close()


def expect(request, request_line, *, status, **options):
    reply = request(request_line, **options)
    if reply.status != status:
        raise RuntimeError(f"{request_line}: expected {status}, got {reply.status}")
    return json.loads(reply.body) if reply.body else None, reply.headers


def login(request, username):
    _, headers = expect(request, "POST /app/login", status=200,
                        body={"username": username, "password": f"{username}-password"})
    return headers["Set-Cookie"].split(";", 1)[0]
