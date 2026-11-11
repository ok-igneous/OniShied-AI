#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${ONISHIELD_BASE_URL:-http://127.0.0.1:3000}"
TOKEN="${LAB_CONNECTOR_TOKEN:-}"
EVENT_FILE="${1:-fixtures/events/authentication-failure.json}"

case "$BASE_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *)
    echo "Refusing to send synthetic events anywhere except localhost." >&2
    exit 2
    ;;
esac

if [[ -z "$TOKEN" ]]; then
  echo "Set LAB_CONNECTOR_TOKEN in the shell environment first." >&2
  exit 2
fi

if [[ ! -f "$EVENT_FILE" ]]; then
  echo "Event fixture not found: $EVENT_FILE" >&2
  exit 2
fi

response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT

status="$(curl --silent --show-error --connect-timeout 3 --max-time 10 \
  -o "$response_file" -w "%{http_code}" \
  -X POST "$BASE_URL/v1/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary "@$EVENT_FILE")"

cat "$response_file"
printf '\nHTTP %s\n' "$status"

if [[ "$status" != "202" && "$status" != "200" ]]; then
  echo "Unexpected ingestion status." >&2
  exit 1
fi
