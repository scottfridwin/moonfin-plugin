#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   export API_KEY="<your_jellyfin_api_key>"
#   export BASE_URL="http://192.168.0.70:10172"    # optional, defaults to http://127.0.0.1:8096
#   export SLUG="<oidc-provider-slug>"
#   export RETURN_URL="https://your.return/url"   # optional
#   ./scripts/test_oidc_flow.sh

BASE_URL="${BASE_URL:-http://127.0.0.1:8096}"
API_KEY="${API_KEY:-}"
SLUG="${SLUG:-}"
RETURN_URL="${RETURN_URL:-}"

if [ -z "$API_KEY" ]; then
  echo "ERROR: Set API_KEY environment variable." >&2
  exit 2
fi
if [ -z "$SLUG" ]; then
  echo "ERROR: Set SLUG environment variable (the Seerr OIDC provider slug)." >&2
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is required." >&2
  exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "WARNING: jq not found. Responses will not be pretty-printed." >&2
fi

AUTH_HDR="Authorization: MediaBrowser Client=\"curl\", Device=\"CLI\", DeviceId=\"moonfin-test\", Version=\"1.0\", Token=\"${API_KEY}\""

echo "Using BASE_URL=${BASE_URL}  SLUG=${SLUG}"

echo -n "Checking plugin status... "
status=$(curl -s -H "$AUTH_HDR" "${BASE_URL}/Moonfin/Jellyseerr/Status" || true)
if command -v jq >/dev/null 2>&1; then
  echo
  echo "$status" | jq .
else
  echo "$status"
fi

echo
echo "Initiating OIDC login (this returns a redirectUrl)..."
returnParam=()
if [ -n "$RETURN_URL" ]; then
  returnParam+=(--data-urlencode "returnUrl=${RETURN_URL}")
fi
resp=$(curl -s -H "$AUTH_HDR" --get "${returnParam[@]}" "${BASE_URL}/Moonfin/Jellyseerr/Oidc/Login/${SLUG}" || true)
if [ -z "$resp" ]; then
  echo "No response from server; aborting." >&2
  exit 3
fi

if command -v jq >/dev/null 2>&1; then
  echo "$resp" | jq .
  redirectUrl=$(echo "$resp" | jq -r '.redirectUrl // empty')
else
  echo "$resp"
  redirectUrl=$(echo "$resp" | sed -n 's/.*"redirectUrl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi

if [ -z "$redirectUrl" ]; then
  echo "Server did not return a redirectUrl. Check the response above for errors." >&2
  exit 4
fi

echo
echo "Opening the following URL will start the OIDC flow:"
echo "- Seerr will redirect you to your OIDC provider (Authentik)"
echo "- You authenticate with your OIDC provider"
echo "- The OIDC provider redirects you back to Seerr's callback endpoint"
echo "- Capture the FINAL Seerr callback URL (look in the browser address bar after redirect)"
echo
echo "Seerr OIDC login URL:"
echo "$redirectUrl"
echo

read -rp "After completing authentication with your OIDC provider, Seerr will redirect you back to a URL like 'https://seerr.fridwin.com/login?code=...&state=...' — paste that final callback URL: " CALLBACK_URL
if [ -z "$CALLBACK_URL" ]; then
  echo "No callback URL provided; aborting." >&2
  exit 5
fi

if command -v jq >/dev/null 2>&1; then
  payload=$(jq -n --arg url "$CALLBACK_URL" '{callbackUrl:$url}')
else
  # crude JSON escape
  esc=$(printf '%s' "$CALLBACK_URL" | sed 's/\\/\\\\/g; s/"/\\"/g')
  payload="{\"callbackUrl\":\"$esc\"}"
fi

echo
echo "Posting callback to the plugin..."
post=$(curl -s -H "$AUTH_HDR" -H 'Content-Type: application/json' -d "$payload" "${BASE_URL}/Moonfin/Jellyseerr/Oidc/Callback/${SLUG}" || true)

if command -v jq >/dev/null 2>&1; then
  echo "$post" | jq .
else
  echo "$post"
fi

echo
echo "Done. If the callback succeeded you should see 'success: true' and Seerr user info." 
