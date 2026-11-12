"""Signed tickets as described in SPEC.md."""
import base64
import hashlib
import hmac
import json
import time


class TicketError(Exception):
    pass


def _mac(key: bytes, body: str) -> str:
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def issue(key: bytes, sub: str, aud: str, ttl: int = 300) -> str:
    payload = {"alg": "HS256", "sub": sub, "aud": aud, "exp": int(time.time()) + ttl}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    return f"{body}.{_mac(key, body)}"


class Verifier:
    def __init__(self, key: bytes, audience: str):
        self.key = key
        self.audience = audience

    def verify(self, ticket: str) -> dict:
        try:
            body, mac = ticket.split(".", 1)
        except ValueError:
            raise TicketError("malformed ticket")
        if not hmac.compare_digest(_mac(self.key, body), mac):
            raise TicketError("bad signature")
        try:
            payload = json.loads(base64.urlsafe_b64decode(body))
        except ValueError:
            raise TicketError("bad payload")
        if not isinstance(payload, dict):
            raise TicketError("payload is not an object")
        if payload.get("alg") != "HS256":
            raise TicketError("unsupported alg")
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= time.time():
            raise TicketError("expired")
        return payload
