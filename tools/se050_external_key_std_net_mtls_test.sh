#!/usr/bin/env bash
set -euo pipefail

SE050CTL="se050ctl"
PROVIDER="/usr/local/lib/libsssProvider.so"
IDENTITY="0"
SLOT="A"
BUS="0"
ADDRESS="0x48"
SSS_PORT="${EX_SSS_BOOT_SSS_PORT:-/dev/i2c-0:0x48}"
BASE_PORT="18453"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
MTLS_TEST="$SCRIPT_DIR/se050_std_net_mtls_test.sh"
CLIENT_BIN="$SCRIPT_DIR/std_net_mtls_client"

usage() {
  cat <<USAGE
Usage: $0 [options]

Import a disposable external P-256 key into one EMPTY test TLS identity slot,
then run the ordinary Nim std/net mutual-TLS test against that imported key.

The test proves the complete path:

  external software key
    -> se050ctl tls-key-import
    -> external-origin SE050 identity
    -> NXP Reference Key
    -> plain Nim std/net certFile/keyFile/caFile
    -> TLS 1.3 mTLS
    -> TLS 1.2 mTLS

Only the test TLS object range is supported. The target object must be missing
before the test starts. An existing object is never overwritten or deleted.

Options:
  --se050ctl PATH       se050ctl executable (default: se050ctl)
  --provider PATH       NXP OpenSSL Provider (default: /usr/local/lib/libsssProvider.so)
  --identity N          test TLS identity number (default: 0)
  --slot A|B            empty test TLS identity slot (default: A)
  --bus N               I2C bus (default: 0)
  --address HEX         SE050 I2C address (default: 0x48)
  --sss-port VALUE      EX_SSS_BOOT_SSS_PORT value (default: /dev/i2c-0:0x48)
  --base-port N         TLS 1.3 port; TLS 1.2 uses N+1 (default: 18453)
  --client PATH         prebuilt ARM64 std/net client
                        (default: tools/std_net_mtls_client beside this script)
  --mtls-test PATH      std/net mTLS integration script
                        (default: tools/se050_std_net_mtls_test.sh beside this script)
  -h, --help            show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --se050ctl) SE050CTL="$2"; shift 2 ;;
    --provider) PROVIDER="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --slot) SLOT="$2"; shift 2 ;;
    --bus) BUS="$2"; shift 2 ;;
    --address) ADDRESS="$2"; shift 2 ;;
    --sss-port) SSS_PORT="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --client) CLIENT_BIN="$2"; shift 2 ;;
    --mtls-test) MTLS_TEST="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

SLOT="${SLOT^^}"
if [[ "$SLOT" != "A" && "$SLOT" != "B" ]]; then
  echo "--slot must be A or B" >&2
  exit 2
fi

if ! [[ "$IDENTITY" =~ ^[0-9]+$ ]]; then
  echo "--identity must be a non-negative decimal integer" >&2
  exit 2
fi

# Mirrors TlsIdentityMaxIdentity from tls/profile.nim:
#   (0xffff - 0x0200) / 2 = 32511
if (( 10#$IDENTITY > 32511 )); then
  echo "--identity is outside the supported TLS identity range: 0..32511" >&2
  exit 2
fi

if ! [[ "$BASE_PORT" =~ ^[0-9]+$ ]] ||
    (( BASE_PORT < 1024 || BASE_PORT > 65534 )); then
  echo "--base-port must be in 1024..65534" >&2
  exit 2
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

if [[ ! -r "$MTLS_TEST" ]]; then
  echo "std/net mTLS test script is not readable: $MTLS_TEST" >&2
  exit 1
fi

if [[ ! -x "$CLIENT_BIN" ]]; then
  echo "prebuilt Nim std/net client is not executable: $CLIENT_BIN" >&2
  exit 1
fi

slot_offset=0
if [[ "$SLOT" == "B" ]]; then
  slot_offset=1
fi

object_id_value=$((0x30000200 + 10#$IDENTITY * 2 + slot_offset))
printf -v OBJECT_ID '0x%08X' "$object_id_value"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/se050-external-std-net-mtls.XXXXXX")"
echo "workdir: $WORKDIR"
echo "test object: $OBJECT_ID (identity $IDENTITY slot $SLOT)"

export EX_SSS_BOOT_SSS_PORT="$SSS_PORT"

SOURCE_KEY="$WORKDIR/source.key"
SOURCE_CERT="$WORKDIR/source.crt"
PREFLIGHT_LOG="$WORKDIR/preflight.log"
IMPORT_LOG="$WORKDIR/import.log"
IMPORTED_INFO_LOG="$WORKDIR/imported-info.log"
CLEANUP_LOG="$WORKDIR/cleanup.log"

# Once this becomes 1, the target was proven missing before any mutation.
# From that point onward, an object appearing at OBJECT_ID belongs to this test.
OWN_EMPTY_SLOT=0

object_status() {
  local log_path="$1"
  local rc

  if "$SE050CTL" exists \
      -b "$BUS" \
      -a "$ADDRESS" \
      --id "$OBJECT_ID" \
      >"$log_path" 2>&1; then
    return 0
  else
    rc=$?
  fi

  if (( rc == 1 )) && grep -Fq "${OBJECT_ID}: missing" "$log_path"; then
    return 1
  fi

  echo "could not determine SE050 object state for $OBJECT_ID" >&2
  echo "see $log_path" >&2
  return 2
}

cleanup_test_object() {
  local saved_rc=$?
  local status_rc
  local delete_rc
  trap - EXIT

  # The source private key is disposable host-side test material and is not
  # retained with the diagnostic logs.
  rm -f -- "$SOURCE_KEY"

  if (( OWN_EMPTY_SLOT == 1 )); then
    if object_status "$WORKDIR/cleanup-status.log"; then
      status_rc=0
    else
      status_rc=$?
    fi

    if (( status_rc == 0 )); then
      echo "cleanup: deleting test object $OBJECT_ID"
      if "$SE050CTL" delete \
          -b "$BUS" \
          -a "$ADDRESS" \
          --id "$OBJECT_ID" \
          >"$CLEANUP_LOG" 2>&1; then
        delete_rc=0
      else
        delete_rc=$?
      fi

      if (( delete_rc != 0 )); then
        echo "cleanup failed for $OBJECT_ID; see $CLEANUP_LOG" >&2
        if (( saved_rc == 0 )); then
          saved_rc=1
        fi
      else
        echo "cleanup: test object deleted"
      fi
    elif (( status_rc == 2 )); then
      echo "cleanup could not determine whether $OBJECT_ID exists" >&2
      if (( saved_rc == 0 )); then
        saved_rc=1
      fi
    fi
  fi

  exit "$saved_rc"
}
trap cleanup_test_object EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if object_status "$PREFLIGHT_LOG"; then
  preflight_rc=0
else
  preflight_rc=$?
fi

case "$preflight_rc" in
  0)
    echo "refusing destructive test: $OBJECT_ID already exists" >&2
    echo "choose another test identity/slot; the existing object was not modified" >&2
    exit 1
    ;;
  1)
    OWN_EMPTY_SLOT=1
    echo "preflight: target test slot is empty"
    ;;
  *)
    exit 1
    ;;
esac

# This certificate is used only for the pre-write key/certificate match check
# in tls-key-import. The actual mTLS client certificate is generated later by
# se050_std_net_mtls_test.sh from the imported SE050 Reference Key.
OPENSSL_CONF=/dev/null openssl genpkey \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -out "$SOURCE_KEY" \
  >/dev/null 2>&1
chmod 600 "$SOURCE_KEY"

OPENSSL_CONF=/dev/null openssl req \
  -new \
  -x509 \
  -sha256 \
  -days 1 \
  -key "$SOURCE_KEY" \
  -subj "/CN=se050-external-import-mtls-${IDENTITY}-${SLOT}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=clientAuth" \
  -out "$SOURCE_CERT" \
  >/dev/null 2>&1

"$SE050CTL" tls-key-import \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --key "$SOURCE_KEY" \
  --cert "$SOURCE_CERT" \
  >"$IMPORT_LOG" 2>&1

"$SE050CTL" tls-key-info \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --imported \
  >"$IMPORTED_INFO_LOG" 2>&1

if ! grep -Fq 'origin: external' "$IMPORTED_INFO_LOG"; then
  echo "imported-origin validation did not report an external origin" >&2
  echo "see $IMPORTED_INFO_LOG" >&2
  exit 1
fi

echo "external P-256 key import: OK"
echo "imported-origin live validation: OK"

bash "$MTLS_TEST" \
  --se050ctl "$SE050CTL" \
  --provider "$PROVIDER" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --bus "$BUS" \
  --address "$ADDRESS" \
  --sss-port "$SSS_PORT" \
  --base-port "$BASE_PORT" \
  --client "$CLIENT_BIN" \
  --imported

echo "external P-256 import + Nim std/net TLS 1.3/TLS 1.2 mTLS: PASS"
