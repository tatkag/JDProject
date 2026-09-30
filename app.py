import os
from flask import Flask, request
from dotenv import load_dotenv
import hmac
import hashlib
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("webhook")
seen_ids = set()  # in-memory only; a real system would use a database



load_dotenv()
app = Flask(__name__)
VERIFY_TOKEN = os.environ["VERIFY_TOKEN"]
APP_SECRET = os.environ["APP_SECRET"]


def mask(number: str) -> str:
    return "***" + number[-4:] if number else "?"

def handle_event(payload: dict) -> None:
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})

            for msg in value.get("messages", []):
                msg_id = msg.get("id")
                if msg_id in seen_ids:
                    log.info("duplicate message ignored id=%s", msg_id)
                    continue
                seen_ids.add(msg_id)
                body = msg.get("text", {}).get("body", "") if msg.get("type") == "text" else ""
                log.info("incoming message id=%s from=%s type=%s text=%r",
                         msg_id, mask(msg.get("from")), msg.get("type"), body)

            for st in value.get("statuses", []):
                errors = st.get("errors")
                level = logging.WARNING if st.get("status") == "failed" else logging.INFO
                log.log(level, "status id=%s status=%s to=%s errors=%s",
                        st.get("id"), st.get("status"), mask(st.get("recipient_id")), errors)

def valid_signature(raw_body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(APP_SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))

@app.get("/webhook")
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "Forbidden", 403


@app.post("/webhook")
def receive():
    raw = request.get_data()
    if not valid_signature(raw, request.headers.get("X-Hub-Signature-256")):
        log.warning("rejected request: bad or missing signature")
        return "Invalid signature", 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        log.warning("rejected request: body is not valid JSON")
        return "Bad request", 400
    handle_event(payload)
    return "OK", 200