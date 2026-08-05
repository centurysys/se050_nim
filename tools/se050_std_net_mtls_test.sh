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
BASE_PORT="18453"
IMPORTED=0

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_BIN="$SCRIPT_DIR/std_net_mtls_client"

usage() {
  cat <<USAGE
Usage: $0 [options]

Run a local mutual-TLS test with a plain Nim std/net client. The Nim client
uses only certFile/keyFile/caFile and contains no NXP Provider or SE050 API.
Provider loading is controlled entirely through OPENSSL_CONF.

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
  --base-port N         TLS 1.3 port; TLS 1.2 uses N+1 (default: 18453)
  --client PATH          prebuilt ARM64 std/net client
                         (default: tools/std_net_mtls_client beside this script)
  --imported             require an externally imported TLS identity
                         (default: internally generated identity)
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
    --client) CLIENT_BIN="$2"; shift 2 ;;
    --imported) IMPORTED=1; shift ;;
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

if [[ "$PROVIDER" == *$'\n'* || "$PROVIDER" == *$'\r'* ]]; then
  echo "provider path must not contain a newline" >&2
  exit 2
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl was not found" >&2
  exit 1
fi

if [[ ! -x "$CLIENT_BIN" ]]; then
  echo "prebuilt Nim std/net client is not executable: $CLIENT_BIN" >&2
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

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/se050-std-net-mtls.XXXXXX")"
echo "workdir: $WORKDIR"

export EX_SSS_BOOT_SSS_PORT="$SSS_PORT"

origin_args=()
if (( IMPORTED == 1 )); then
  origin_args+=(--imported)
  echo "TLS identity provisioning: externally imported"
else
  echo "TLS identity provisioning: SE050 internally generated"
fi

REFERENCE_KEY="$WORKDIR/device.key"
LIVE_PUBLIC_DER="$WORKDIR/se050-public.der"
CLIENT_PUBLIC_DER="$WORKDIR/client-public.der"
OPENSSL_CNF="$WORKDIR/openssl.cnf"

"$SE050CTL" tls-key-ref-file \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile "$PROFILE" \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  "${origin_args[@]}" \
  --out "$REFERENCE_KEY"

mode="$(stat -c '%a' "$REFERENCE_KEY")"
if [[ "$mode" != "600" ]]; then
  echo "unexpected reference-key permissions: $mode (expected 600)" >&2
  exit 1
fi

echo "reference-key permissions: 0600"

"$SE050CTL" tls-key-pubkey \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile "$PROFILE" \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  "${origin_args[@]}" \
  --format spki-der \
  --out "$LIVE_PUBLIC_DER"

cat > "$OPENSSL_CNF" <<EOF_CNF
config_diagnostics = 1
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
nxp_prov = nxp_sect
default = default_sect

[nxp_sect]
identity = nxp_prov
module = $PROVIDER
activate = 1

[default_sect]
activate = 1
EOF_CNF

# Generate only the test CA and server identity in software. The client CSR
# uses the ordinary reference-key filename with Provider loading supplied only
# by OPENSSL_CONF.
OPENSSL_CONF=/dev/null openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$WORKDIR/ca.key" \
  >/dev/null 2>&1

OPENSSL_CONF=/dev/null openssl req \
  -x509 \
  -new \
  -sha256 \
  -days 1 \
  -key "$WORKDIR/ca.key" \
  -subj "/CN=se050-std-net-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out "$WORKDIR/ca.crt" \
  >/dev/null 2>&1

OPENSSL_CONF=/dev/null openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$WORKDIR/server.key" \
  >/dev/null 2>&1

OPENSSL_CONF=/dev/null openssl req \
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

OPENSSL_CONF=/dev/null openssl x509 \
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

OPENSSL_CONF="$OPENSSL_CNF" openssl req \
  -new \
  -sha256 \
  -key "$REFERENCE_KEY" \
  -subj "/CN=se050-std-net-client-${IDENTITY}-${SLOT}" \
  -out "$WORKDIR/client.csr" \
  > "$WORKDIR/client-csr.stdout" \
  2> "$WORKDIR/client-csr.stderr"

OPENSSL_CONF=/dev/null openssl req \
  -in "$WORKDIR/client.csr" \
  -noout \
  -verify \
  > "$WORKDIR/client-csr-verify.log" \
  2>&1

cat > "$WORKDIR/client.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT

OPENSSL_CONF=/dev/null openssl x509 \
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

# Validate the software-generated test PKI before involving Nim or the NXP
# Provider. This gives a direct error if the local test certificates are not
# valid for their intended TLS purposes.
OPENSSL_CONF=/dev/null openssl verify \
  -CAfile "$WORKDIR/ca.crt" \
  -purpose sslserver \
  -verify_hostname localhost \
  "$WORKDIR/server.crt" \
  > "$WORKDIR/server-cert-verify.log" 2>&1

OPENSSL_CONF=/dev/null openssl verify \
  -CAfile "$WORKDIR/ca.crt" \
  -purpose sslclient \
  "$WORKDIR/client.crt" \
  > "$WORKDIR/client-cert-verify.log" 2>&1

echo "test PKI certificate purposes: OK"

OPENSSL_CONF=/dev/null openssl x509 \
  -in "$WORKDIR/client.crt" \
  -pubkey \
  -noout 2>/dev/null | \
OPENSSL_CONF=/dev/null openssl pkey \
  -pubin \
  -outform DER \
  -out "$CLIENT_PUBLIC_DER" \
  >/dev/null 2>&1

if ! cmp -s "$LIVE_PUBLIC_DER" "$CLIENT_PUBLIC_DER"; then
  echo "client certificate public key does not match the live SE050 object" >&2
  exit 1
fi

echo "client certificate public key: matches live SE050 object"

# The application under test is cross-built in advance and copied to the
# target. It imports only std/net and receives the certificate/key paths like
# an ordinary OpenSSL-backed Nim application.
echo "prebuilt Nim std/net client: $CLIENT_BIN"

run_nim_handshake() {
  local tls_option="$1"
  local label="$2"
  local port="$3"
  local server_log="$WORKDIR/server-${label}.log"
  local client_log="$WORKDIR/nim-client-${label}.log"

  local -a server_tls_args=("$tls_option")

  # TLS 1.3 with the same reference key already succeeds. For TLS 1.2,
  # constrain the test to an ECDHE-ECDSA cipher actually offered by the Nim/
  # OpenSSL client, P-256, and ECDSA/SHA-256 for client CertificateVerify.
  if [[ "$label" == "tls1_2" ]]; then
    server_tls_args+=(
      -cipher ECDHE-ECDSA-AES128-GCM-SHA256
      -named_curve prime256v1
      -client_sigalgs ECDSA+SHA256
      -state
      -msg
    )
  fi

  OPENSSL_CONF=/dev/null openssl s_server \
    -accept "127.0.0.1:${port}" \
    "${server_tls_args[@]}" \
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
  OPENSSL_CONF="$OPENSSL_CNF" \
  EX_SSS_BOOT_SSS_PORT="$SSS_PORT" \
    "$CLIENT_BIN" \
      127.0.0.1 \
      "$port" \
      "$WORKDIR/ca.crt" \
      "$WORKDIR/client.crt" \
      "$REFERENCE_KEY" \
      localhost \
      > "$client_log" 2>&1
  local client_rc=$?

  wait "$server_pid"
  local server_rc=$?
  set -e

  if (( client_rc != 0 )); then
    echo "$label Nim std/net client failed with exit code $client_rc" >&2
    echo "see $client_log" >&2
    if [[ "$label" == "tls1_2" ]]; then
      echo "TLS 1.2 server diagnostic log: $server_log" >&2
    fi
    return 1
  fi

  if (( server_rc != 0 )); then
    echo "$label OpenSSL test server failed with exit code $server_rc" >&2
    echo "see $server_log" >&2
    return 1
  fi

  if ! grep -q 'std/net mutual TLS: OK' "$client_log"; then
    echo "$label Nim client did not report a successful mTLS handshake" >&2
    echo "see $client_log" >&2
    return 1
  fi

  if ! grep -q "se050-std-net-client-${IDENTITY}-${SLOT}" "$server_log"; then
    echo "$label server did not verify the expected client certificate" >&2
    echo "see $server_log" >&2
    return 1
  fi

  echo "$label Nim std/net mutual TLS: OK"
}

run_nim_handshake -tls1_3 tls1_3 "$BASE_PORT"
run_nim_handshake -tls1_2 tls1_2 "$((BASE_PORT + 1))"

echo "OpenSSL config: $OPENSSL_CNF"
echo "reference key: $REFERENCE_KEY"
echo "client certificate: $WORKDIR/client.crt"
echo "Nim client binary: $CLIENT_BIN"
echo "Nim std/net transparent SE050 mTLS test: PASS"
