#!/bin/bash
# usage: ./send.sh samples/message.json

source .env

SECRET="${APP_SECRET:?APP_SECRET must be set in .env}"
SIG=$(openssl dgst -sha256 -hmac "$SECRET" < "$1" | sed 's/^.* //')
curl -i -X POST http://127.0.0.1:5000/webhook \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIG" \
  --data-binary @"$1"