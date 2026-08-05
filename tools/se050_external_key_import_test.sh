#!/usr/bin/env bash
set -euo pipefail

SE050CTL="se050ctl"
PROVIDER="/usr/local/lib/libsssProvider.so"
IDENTITY="0"
SLOT="B"
BUS="0"
ADDRESS="0x48"
SSS_PORT="${EX_SSS_BOOT_SSS_PORT:-/dev/i2c-0:0x48}"

usage() {
  cat <<USAGE
Usage: $0 [options]

Destructively exercise one EMPTY test TLS identity slot with an externally
generated P-256 private key:

  software key/certificate
    -> se050ctl tls-key-import
    -> imported-origin live validation
    -> public-key comparison
    -> NXP reference-key export
    -> Provider-backed signature
    -> independent software verification
    -> test object deletion

Only the test/development TLS object range is supported. The target object must
be missing before the test starts; an existing object is never deleted or
replaced.

Options:
  --se050ctl PATH       se050ctl executable (default: se050ctl)
  --provider PATH       NXP OpenSSL Provider (default: /usr/local/lib/libsssProvider.so)
  --identity N          test TLS identity number (default: 0)
  --slot A|B            empty test TLS identity slot (default: B)
  --bus N               I2C bus (default: 0)
  --address HEX         SE050 I2C address (default: 0x48)
  --sss-port VALUE      EX_SSS_BOOT_SSS_PORT value (default: /dev/i2c-0:0x48)
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

if [[ "$SE050CTL" == */* ]]; then
  if [[ ! -x "$SE050CTL" ]]; then
    echo "se050ctl is not executable: $SE050CTL" >&2
    exit 1
  fi
elif ! command -v "$SE050CTL" >/dev/null 2>&1; then
  echo "se050ctl was not found: $SE050CTL" >&2
  exit 1
fi

slot_offset=0
if [[ "$SLOT" == "B" ]]; then
  slot_offset=1
fi

object_id_value=$((0x30000200 + 10#$IDENTITY * 2 + slot_offset))
printf -v OBJECT_ID '0x%08X' "$object_id_value"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/se050-external-key-import.XXXXXX")"
echo "workdir: $WORKDIR"
echo "test object: $OBJECT_ID (identity $IDENTITY slot $SLOT)"

export EX_SSS_BOOT_SSS_PORT="$SSS_PORT"

SOURCE_KEY="$WORKDIR/source.key"
SOURCE_CERT="$WORKDIR/source.crt"
SOURCE_PUBLIC_DER="$WORKDIR/source-public.der"
SOURCE_PUBLIC_PEM="$WORKDIR/source-public.pem"
LIVE_PUBLIC_DER="$WORKDIR/live-public.der"
REFERENCE_KEY="$WORKDIR/reference.key"
REFERENCE_PUBLIC_DER="$WORKDIR/reference-public.der"
INPUT="$WORKDIR/input.txt"
SIGNATURE="$WORKDIR/signature.der"
OPENSSL_CNF="$WORKDIR/openssl.cnf"

PREFLIGHT_LOG="$WORKDIR/preflight.log"
IMPORT_LOG="$WORKDIR/import.log"
INTERNAL_INFO_LOG="$WORKDIR/internal-info.log"
IMPORTED_INFO_LOG="$WORKDIR/imported-info.log"
SIGN_LOG="$WORKDIR/provider-sign.log"
VERIFY_LOG="$WORKDIR/software-verify.log"
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

# Generate only disposable host-side test material. OPENSSL_CONF=/dev/null keeps
# any system NXP Provider configuration out of software key generation.
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
  -subj "/CN=se050-external-import-${IDENTITY}-${SLOT}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=clientAuth" \
  -out "$SOURCE_CERT" \
  >/dev/null 2>&1

OPENSSL_CONF=/dev/null openssl pkey \
  -in "$SOURCE_KEY" \
  -pubout \
  -outform DER \
  -out "$SOURCE_PUBLIC_DER" \
  >/dev/null 2>&1

OPENSSL_CONF=/dev/null openssl pkey \
  -in "$SOURCE_KEY" \
  -pubout \
  -out "$SOURCE_PUBLIC_PEM" \
  >/dev/null 2>&1

# Enable debug deliberately for the import. The sensitive WriteECKey exchange
# must be redacted by transport.nim rather than dumping the private scalar.
"$SE050CTL" tls-key-import \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --key "$SOURCE_KEY" \
  --cert "$SOURCE_CERT" \
  --debug \
  >"$IMPORT_LOG" 2>&1

if ! grep -Fq 'T1 TX: <redacted sensitive frame,' "$IMPORT_LOG"; then
  echo "sensitive key-import TX frame was not reported as redacted" >&2
  echo "see $IMPORT_LOG" >&2
  exit 1
fi

if ! grep -Fq 'T1 RX: <redacted sensitive frame,' "$IMPORT_LOG"; then
  echo "sensitive key-import RX frame was not reported as redacted" >&2
  echo "see $IMPORT_LOG" >&2
  exit 1
fi

echo "sensitive WriteECKey transport logging: redacted"

# The default inspection path must remain strict for internally generated keys.
set +e
"$SE050CTL" tls-key-info \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  >"$INTERNAL_INFO_LOG" 2>&1
internal_info_rc=$?
set -e

if (( internal_info_rc == 0 )); then
  echo "default internal-origin validation unexpectedly accepted imported key" >&2
  echo "see $INTERNAL_INFO_LOG" >&2
  exit 1
fi

echo "internal-origin validation rejects imported key: OK"

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

echo "imported-origin live attestation validation: OK"

"$SE050CTL" tls-key-pubkey \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --imported \
  --format spki-der \
  --out "$LIVE_PUBLIC_DER" \
  >/dev/null

if ! cmp -s "$SOURCE_PUBLIC_DER" "$LIVE_PUBLIC_DER"; then
  echo "live SE050 public key does not match the source external key" >&2
  exit 1
fi

echo "imported public key: matches source external key"

"$SE050CTL" tls-key-ref-file \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile test \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --imported \
  --out "$REFERENCE_KEY" \
  >/dev/null

mode="$(stat -c '%a' "$REFERENCE_KEY")"
if [[ "$mode" != "600" ]]; then
  echo "unexpected reference-key permissions: $mode (expected 600)" >&2
  exit 1
fi

OPENSSL_CONF=/dev/null openssl ec \
  -in "$REFERENCE_KEY" \
  -pubout \
  -outform DER \
  -out "$REFERENCE_PUBLIC_DER" \
  >/dev/null 2>&1

if ! cmp -s "$SOURCE_PUBLIC_DER" "$REFERENCE_PUBLIC_DER"; then
  echo "reference-key public key does not match the imported source key" >&2
  exit 1
fi

echo "reference-key public key: matches imported source key"

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

printf 'SE050 external P-256 import Provider test\n' > "$INPUT"

set +e
OPENSSL_CONF="$OPENSSL_CNF" \
EX_SSS_BOOT_SSS_PORT="$SSS_PORT" \
openssl pkeyutl \
  -inkey "$REFERENCE_KEY" \
  -sign \
  -rawin \
  -in "$INPUT" \
  -out "$SIGNATURE" \
  -digest sha256 \
  >"$SIGN_LOG" 2>&1
sign_rc=$?
set -e

if (( sign_rc != 0 )); then
  echo "NXP Provider signing with the imported SE050 key failed" >&2
  echo "see $SIGN_LOG" >&2
  exit 1
fi

if [[ ! -s "$SIGNATURE" ]]; then
  echo "NXP Provider produced an empty signature" >&2
  exit 1
fi

set +e
OPENSSL_CONF=/dev/null openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$SOURCE_PUBLIC_PEM" \
  -rawin \
  -in "$INPUT" \
  -sigfile "$SIGNATURE" \
  -digest sha256 \
  >"$VERIFY_LOG" 2>&1
verify_rc=$?
set -e

if (( verify_rc != 0 )); then
  echo "signature verification against the original software public key failed" >&2
  echo "see $VERIFY_LOG" >&2
  exit 1
fi

echo "NXP Provider sign with imported key: OK"
echo "software verify with original public key: OK"
echo "external P-256 TLS key import integration test: PASS"
