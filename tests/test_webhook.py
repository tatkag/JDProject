import hashlib
import hmac
import logging
import os
from pathlib import Path

# set test secrets BEFORE importing the app; load_dotenv() won't override these
os.environ["VERIFY_TOKEN"] = "test-verify"
os.environ["APP_SECRET"] = "test-secret"

import pytest
import app as app_module

SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    app_module.seen_ids.clear()
    return app_module.app.test_client()


def sign(body: bytes) -> str:
    return "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()


def post(client, body: bytes, signature: str | None = None):
    headers = {"Content-Type": "application/json"}
    if signature:
        headers["X-Hub-Signature-256"] = signature
    return client.post("/webhook", data=body, headers=headers)


def test_verification_succeeds_with_correct_token(client):
    r = client.get("/webhook?hub.mode=subscribe&hub.verify_token=test-verify&hub.challenge=1234")
    assert r.status_code == 200 and r.get_data(as_text=True) == "1234"


def test_verification_fails_with_wrong_token(client):
    r = client.get("/webhook?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=1234")
    assert r.status_code == 403


def test_valid_signature_accepted(client):
    body = (SAMPLES / "message.json").read_bytes()
    assert post(client, body, sign(body)).status_code == 200


def test_bad_signature_rejected(client):
    body = (SAMPLES / "message.json").read_bytes()
    assert post(client, body, "sha256=deadbeef").status_code == 403


def test_missing_signature_rejected(client):
    body = (SAMPLES / "message.json").read_bytes()
    assert post(client, body).status_code == 403


def test_invalid_json_with_valid_signature_returns_400(client):
    body = b"not json"
    assert post(client, body, sign(body)).status_code == 400


def test_duplicate_message_is_ignored(client, caplog):
    body = (SAMPLES / "message.json").read_bytes()
    with caplog.at_level(logging.INFO, logger="webhook"):
        post(client, body, sign(body))
        post(client, body, sign(body))
    assert "incoming message" in caplog.text
    assert "duplicate message ignored" in caplog.text


def test_failed_status_logged_as_warning(client, caplog):
    body = (SAMPLES / "status_failed.json").read_bytes()
    with caplog.at_level(logging.INFO, logger="webhook"):
        post(client, body, sign(body))
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("131031" in r.getMessage() for r in warnings)