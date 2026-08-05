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

usage() {
  cat <<USAGE
Usage: $0 [options]

Validate an exported SE050 TLS reference-key PEM through the NXP OpenSSL
Provider. The script never creates, deletes, or replaces an SE050 key.

Options:
  --se050ctl PATH       se050ctl executable (default: se050ctl)
  --provider PATH       NXP OpenSSL Provider (default: /usr/local/lib/libsssProvider.so)
  --profile NAME        test or production (default: test)
  --identity N          TLS identity number (default: 0)
  --slot A|B            TLS identity slot (default: A)
  --bus N               I2C bus for se050ctl validation (default: 0)
  --address HEX         I2C address for se050ctl validation (default: 0x48)
  --sss-port VALUE      EX_SSS_BOOT_SSS_PORT value (default: /dev/i2c-0:0x48)
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

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/se050-ref-provider.XXXXXX")"
echo "workdir: $WORKDIR"

export EX_SSS_BOOT_SSS_PORT="$SSS_PORT"

REFERENCE_KEY="$WORKDIR/device.key"
LIVE_PUBLIC_DER="$WORKDIR/se050-public.der"
REFERENCE_PUBLIC_DER="$WORKDIR/reference-public.der"
VERIFY_PUBLIC_PEM="$WORKDIR/se050-public.pem"
INPUT="$WORKDIR/input.txt"
SIGNATURE="$WORKDIR/signature.der"
SIGN_LOG="$WORKDIR/provider-sign.log"
VERIFY_LOG="$WORKDIR/software-verify.log"

# Export through the production library path. This performs the live TLS
# identity and attestation checks before the reference-key file is written.
"$SE050CTL" tls-key-ref-file \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile "$PROFILE" \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --out "$REFERENCE_KEY"

mode="$(stat -c '%a' "$REFERENCE_KEY")"
if [[ "$mode" != "600" ]]; then
  echo "unexpected reference-key permissions: $mode (expected 600)" >&2
  exit 1
fi

echo "reference-key permissions: 0600"

# Read the independently validated live public key from the SE050.
"$SE050CTL" tls-key-pubkey \
  -b "$BUS" \
  -a "$ADDRESS" \
  --profile "$PROFILE" \
  --identity "$IDENTITY" \
  --slot "$SLOT" \
  --format spki-der \
  --out "$LIVE_PUBLIC_DER"

# Confirm that the public key embedded in the generated reference PEM is the
# same key that was read from the live SE050 object.
openssl ec \
  -in "$REFERENCE_KEY" \
  -pubout \
  -outform DER \
  -out "$REFERENCE_PUBLIC_DER" \
  >/dev/null 2>&1

if ! cmp -s "$LIVE_PUBLIC_DER" "$REFERENCE_PUBLIC_DER"; then
  echo "reference-key public key does not match the live SE050 public key" >&2
  exit 1
fi

echo "reference-key public key: matches live SE050 object"

# Use a plain key filename. NXP documents that file-format reference keys must
# be decoded with the NXP provider loaded before the default provider.
printf 'SE050 OpenSSL reference-key provider test\n' > "$INPUT"

set +e
openssl pkeyutl \
  --provider "$PROVIDER" \
  --provider default \
  -inkey "$REFERENCE_KEY" \
  -sign \
  -rawin \
  -in "$INPUT" \
  -out "$SIGNATURE" \
  -digest sha256 \
  > "$SIGN_LOG" 2>&1
sign_rc=$?
set -e

if (( sign_rc != 0 )); then
  echo "NXP Provider signing with the reference-key file failed" >&2
  echo "see $SIGN_LOG" >&2
  exit 1
fi

if [[ ! -s "$SIGNATURE" ]]; then
  echo "NXP Provider produced an empty signature" >&2
  exit 1
fi

# Verify using only the public key read independently from the SE050. This is
# stronger than checking provider log text: a software signature made from the
# reference metadata would not verify against the real SE050 public key.
openssl pkey \
  -pubin \
  -inform DER \
  -in "$LIVE_PUBLIC_DER" \
  -out "$VERIFY_PUBLIC_PEM" \
  >/dev/null 2>&1

set +e
openssl pkeyutl \
  -verify \
  -pubin \
  -inkey "$VERIFY_PUBLIC_PEM" \
  -rawin \
  -in "$INPUT" \
  -sigfile "$SIGNATURE" \
  -digest sha256 \
  > "$VERIFY_LOG" 2>&1
verify_rc=$?
set -e

if (( verify_rc != 0 )); then
  echo "signature verification against the live SE050 public key failed" >&2
  echo "see $VERIFY_LOG" >&2
  exit 1
fi

echo "reference-key Provider sign: OK"
echo "software verify with live SE050 public key: OK"
echo "reference key: $REFERENCE_KEY"
echo "signature: $SIGNATURE"
echo "provider log: $SIGN_LOG"
echo "reference-key Provider integration test: PASS"
