#!/usr/bin/env bash
set -euo pipefail

SE050CTL="se050ctl"
PROVIDER="/usr/local/lib/libsssProvider.so"
PROFILE="test"
IDENTITY="0"
SLOT="A"
BUS="0"
ADDRESS="0x48"
SSS_PORT="${EX_SSS_BOOT_SSS_PORT:-/dev/i2c-0:0x48}"
BASE_PORT="18443"

usage() {
  cat <<USAGE
Usage: $0 [options]

Run a local mutual-TLS integration test using an existing SE050 TLS identity.
The script never creates, deletes, or replaces an SE050 key.

Options:
  --se050ctl PATH       se050ctl executable (default: se050ctl)
  --provider PATH       NXP OpenSSL Provider (default: /usr/local/lib/libsssProvider.so)
  --profile NAME        test or production (default: test)
  --identity N          TLS identity number (default: 0)
  --slot A|B            TLS identity slot (default: A)
  --bus N               I2C bus for se050ctl validation (default: 0)
  --address HEX         I2C address for se050ctl validation (default: 0x48)
  --sss-port VALUE      EX_SSS_BOOT_SSS_PORT value (default: /dev/i2c-0:0x48)
  --base-port N         TLS 1.3 port; TLS 1.2 uses N+1 (default: 18443)
  -h, --help            show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --se050ctl) SE050CTL="$2"; shift 2 ;;
    --provider) PROVIDER="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --slot) SLOT="$2"; shift 2 ;;
    --bus) BUS="$2"; shift 2 ;;
    --address) ADDRESS="$2"; shift 2 ;;
    --sss-port) SSS_PORT="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$PROFILE" != "test" && "$PROFILE" != "production" ]]; then
  echo "--profile must be test or production" >&2
  exit 2
fi

SLOT="${SLOT^^}"
if [[ "$SLOT" != "A" && "$SLOT" != "B" ]]; then
  echo "--slot must be A or B" >&2
  exit 2
fi

if ! [[ "$IDENTITY" =~ ^[0-9]+$ ]]; then
  echo "--identity must be a non-negative decimal integer" >&2
  exit 2
fi

if ! [[ "$BASE_PORT" =~ ^[0-9]+$ ]] || (( BASE_PORT < 1024 || BASE_PORT > 65534 )); then
  echo "--base-port must be in 1024..65534" >&2
  exit 2
fi

if [[ ! -r "$PROVIDER" ]]; then
  echo "provider is not readable: $PROVIDER" >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl was not found" >&2
  exit 1
fi

if [[ "$SE050CTL" == */* ]]; then
  if [[ ! -x "$SE050CTL" ]]; then
    echo "se050ctl is not executable: $SE050CTL" >&2
    exit 1
  fi
elif ! command -v "$SE050CTL" >/dev/null 2>&1; then
  echo "se050ctl was not found: $SE050CTL" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/se050-local-mtls.XXXXXX")"
echo "workdir: $WORKDIR"

export EX_SSS_BOOT_SSS_PORT="$SSS_PORT"

# Validate the selected object through the same live/attestation checks used by
# se050ctl before OpenSSL is allowed to use it.
"$SE050CTL" tls-key-info \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile "$PROFILE" \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  > "$WORKDIR/se050-key-info.txt"

KEY_URI="$("$SE050CTL" tls-key-ref \
  --profile "$PROFILE" \
  --identity "$IDENTITY" \
  --slot "$SLOT")"

case "$KEY_URI" in
  nxp:0x????????) ;;
  *)
    echo "unexpected NXP Provider key URI: $KEY_URI" >&2
    exit 1
    ;;
esac

echo "key URI: $KEY_URI"

# Local test CA. This key is intentionally software-only; only the TLS client
# private key is under test and remains inside the SE050.
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$WORKDIR/ca.key" \
  >/dev/null 2>&1

openssl req \
  -x509 \
  -new \
  -sha256 \
  -days 1 \
  -key "$WORKDIR/ca.key" \
  -subj "/CN=se050-local-test-ca" \
  -out "$WORKDIR/ca.crt" \
  >/dev/null 2>&1

# Local TLS server certificate with localhost SAN.
openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$WORKDIR/server.key" \
  >/dev/null 2>&1

openssl req \
  -new \
  -sha256 \
  -key "$WORKDIR/server.key" \
  -subj "/CN=localhost" \
  -out "$WORKDIR/server.csr" \
  >/dev/null 2>&1

cat > "$WORKDIR/server.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EXT

openssl x509 \
  -req \
  -sha256 \
  -days 1 \
  -in "$WORKDIR/server.csr" \
  -CA "$WORKDIR/ca.crt" \
  -CAkey "$WORKDIR/ca.key" \
  -CAcreateserial \
  -extfile "$WORKDIR/server.ext" \
  -out "$WORKDIR/server.crt" \
  >/dev/null 2>&1

# Generate the client CSR through the NXP Provider. The private key is never
# materialized as a host file.
openssl req \
  -new \
  -sha256 \
  -provider "$PROVIDER" \
  -provider default \
  -key "$KEY_URI" \
  -subj "/CN=se050-local-client-${IDENTITY}-${SLOT}" \
  -out "$WORKDIR/client.csr" \
  > "$WORKDIR/client-csr.stdout" \
  2> "$WORKDIR/client-csr.stderr"

openssl req \
  -in "$WORKDIR/client.csr" \
  -noout \
  -verify \
  > "$WORKDIR/client-csr-verify.txt" \
  2>&1

cat > "$WORKDIR/client.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT

openssl x509 \
  -req \
  -sha256 \
  -days 1 \
  -in "$WORKDIR/client.csr" \
  -CA "$WORKDIR/ca.crt" \
  -CAkey "$WORKDIR/ca.key" \
  -CAserial "$WORKDIR/ca.srl" \
  -extfile "$WORKDIR/client.ext" \
  -out "$WORKDIR/client.crt" \
  >/dev/null 2>&1

openssl verify \
  -CAfile "$WORKDIR/ca.crt" \
  -purpose sslserver \
  "$WORKDIR/server.crt" \
  > "$WORKDIR/server-cert-verify.txt"

openssl verify \
  -CAfile "$WORKDIR/ca.crt" \
  -purpose sslclient \
  "$WORKDIR/client.crt" \
  > "$WORKDIR/client-cert-verify.txt"

run_handshake() {
  local tls_option="$1"
  local label="$2"
  local port="$3"
  local server_log="$WORKDIR/server-${label}.log"
  local client_log="$WORKDIR/client-${label}.log"

  openssl s_server \
    -accept "127.0.0.1:${port}" \
    "$tls_option" \
    -cert "$WORKDIR/server.crt" \
    -key "$WORKDIR/server.key" \
    -CAfile "$WORKDIR/ca.crt" \
    -Verify 1 \
    -verify_return_error \
    -www \
    -naccept 1 \
    > "$server_log" \
    2>&1 &
  local server_pid=$!

  # Give s_server a short opportunity to bind the loopback socket.
  sleep 0.3

  set +e
  printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    openssl s_client \
      -connect "127.0.0.1:${port}" \
      -servername localhost \
      "$tls_option" \
      -provider "$PROVIDER" \
      -provider default \
      -cert "$WORKDIR/client.crt" \
      -key "$KEY_URI" \
      -CAfile "$WORKDIR/ca.crt" \
      -verify_return_error \
      -verify_hostname localhost \
      -quiet \
      > "$client_log" \
      2>&1
  local client_rc=$?
  set -e

  if ! wait "$server_pid"; then
    echo "$label server failed; see $server_log" >&2
    return 1
  fi

  if (( client_rc != 0 )); then
    echo "$label client failed with exit code $client_rc; see $client_log" >&2
    return 1
  fi

  if ! grep -q 'Verify return code: 0 (ok)' "$server_log" && \
     ! grep -q 'verify return:1' "$server_log"; then
    echo "$label server log does not show successful client certificate verification" >&2
    echo "see $server_log" >&2
    return 1
  fi

  if ! grep -q 'Performing ECDSA sign using SE05x' "$client_log"; then
    echo "$label client log does not show SE05x ECDSA signing through the NXP Provider" >&2
    echo "see $client_log" >&2
    return 1
  fi

  echo "$label mutual TLS: OK"
}

run_rejection_control() {
  local port="$1"
  local server_log="$WORKDIR/server-no-client-cert.log"
  local client_log="$WORKDIR/client-no-client-cert.log"

  openssl s_server \
    -accept "127.0.0.1:${port}" \
    -tls1_3 \
    -cert "$WORKDIR/server.crt" \
    -key "$WORKDIR/server.key" \
    -CAfile "$WORKDIR/ca.crt" \
    -Verify 1 \
    -verify_return_error \
    -www \
    -naccept 1 \
    > "$server_log" \
    2>&1 &
  local server_pid=$!

  sleep 0.3

  set +e
  printf 'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n' | \
    openssl s_client \
      -connect "127.0.0.1:${port}" \
      -servername localhost \
      -tls1_3 \
      -CAfile "$WORKDIR/ca.crt" \
      -verify_return_error \
      -verify_hostname localhost \
      -quiet \
      > "$client_log" \
      2>&1
  local client_rc=$?
  wait "$server_pid"
  local server_rc=$?
  set -e

  if (( client_rc == 0 && server_rc == 0 )); then
    echo "negative control unexpectedly accepted a client without a certificate" >&2
    echo "see $server_log and $client_log" >&2
    return 1
  fi

  echo "TLS 1.3 without client certificate: rejected (expected)"
}

run_handshake -tls1_3 tls1_3 "$BASE_PORT"
run_handshake -tls1_2 tls1_2 "$((BASE_PORT + 1))"
run_rejection_control "$((BASE_PORT + 2))"

echo "client certificate: $WORKDIR/client.crt"
echo "client private key: SE050 only ($KEY_URI)"
echo "TLS 1.3 log: $WORKDIR/client-tls1_3.log"
echo "TLS 1.2 log: $WORKDIR/client-tls1_2.log"
echo "local mutual TLS test: PASS"
