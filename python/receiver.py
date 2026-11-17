"""Superslice callback receiver for Python 3.10+. Standard library only.

Run: SUPERSLICE_WEBHOOK_SECRET=whsec_... python3 receiver.py
"""
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("SUPERSLICE_WEBHOOK_SECRET", "")
PORT = int(os.environ.get("PORT", "8000"))
TOLERANCE_S = 300


def verify(secret: str, header: str | None, raw_body: bytes, now: int | None = None) -> bool:
    """True when `header` (the Superslice-Signature value) signs `raw_body` with `secret`
    and its timestamp is within 5 minutes of `now`. Verify the raw bytes, before parsing JSON."""
    now = int(time.time()) if now is None else now
    t, signatures = None, []
    for part in (header or "").split(","):
        key, _, value = part.strip().partition("=")
        if key == "t" and value.isdigit():
            t = int(value)
        elif key == "v1" and value:
            signatures.append(value)
    if t is None or not signatures or abs(now - t) > TOLERANCE_S:
        return False
    expected = hmac.new(secret.encode(), f"{t}.".encode() + raw_body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(s, expected) for s in signatures)


# Superslice may deliver an event more than once. Store event_id in your database in production.
seen: set[str] = set()


def handle(event: dict) -> None:
    if event["event"] == "slice.completed":
        result = event["data"]["result"]
        print(f"slice {event['data']['id']}: {result['print_time_s']} s, {result['filament_g']} g", flush=True)
    elif event["event"] == "slice.failed":
        print(f"slice {event['data']['id']} failed: {event['data']['error']['code']}", flush=True)


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        raw_body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if not verify(SECRET, self.headers.get("Superslice-Signature"), raw_body):
            return self.reply(400, "invalid signature")
        event = json.loads(raw_body)
        if event["event_id"] in seen:
            return self.reply(200, "duplicate")
        seen.add(event["event_id"])
        # Answer quickly; do slow work (emails, orders) after responding or in a queue.
        self.reply(200, "ok")
        handle(event)

    def do_GET(self) -> None:
        self.reply(405, "method not allowed")

    def reply(self, status: int, text: str) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(text)))
        self.end_headers()
        self.wfile.write(text.encode())

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    if not SECRET:
        raise SystemExit("set SUPERSLICE_WEBHOOK_SECRET")
    print(f"listening on {PORT}", flush=True)
    ThreadingHTTPServer(("", PORT), Receiver).serve_forever()
