#!/bin/bash
set -euo pipefail

SE050CTL="se050ctl"
PROVIDER="/usr/local/lib/libsssProvider.so"
BUS="0"
ADDRESS="0x48"
KIND="ecc"
IDENTITY="0"

usage() {
  cat <<'USAGE'
Usage: se050_factory_identity_test.sh [options]

Options:
  --se050ctl PATH     se050ctl executable (default: se050ctl)
  --provider PATH     NXP OpenSSL Provider (default: /usr/local/lib/libsssProvider.so)
  --bus N             I2C bus number (default: 0)
  --address HEX       SE050 I2C address (default: 0x48)
  --kind KIND         Factory identity kind: ecc or rsa (default: ecc)
  --identity N        Factory identity number: 0 or 1 (default: 0)
  -h, --help          Show this help

EX_SSS_BOOT_SSS_PORT must already identify the SE050 for the NXP Provider,
for example /dev/i2c-0:0x48.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --se050ctl)
      SE050CTL="$2"
      shift 2
      ;;
    --provider)
      PROVIDER="$2"
      shift 2
      ;;
    --bus)
      BUS="$2"
      shift 2
      ;;
    --address)
      ADDRESS="$2"
      shift 2
      ;;
    --kind)
      KIND="$2"
      shift 2
      ;;
    --identity)
      IDENTITY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${EX_SSS_BOOT_SSS_PORT:-}" ]]; then
  echo "EX_SSS_BOOT_SSS_PORT is not set" >&2
  echo "example: export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48" >&2
  exit 2
fi

if [[ ! -x "$SE050CTL" ]] && ! command -v "$SE050CTL" >/dev/null 2>&1; then
  echo "se050ctl not found: $SE050CTL" >&2
  exit 2
fi

if [[ ! -r "$PROVIDER" ]]; then
  echo "NXP OpenSSL Provider not found: $PROVIDER" >&2
  exit 2
fi

WORKDIR=$(mktemp -d /tmp/se050-factory-identity.XXXXXX)
CERT="$WORKDIR/factory.crt"
PUBLIC_DER="$WORKDIR/factory-public.der"
OPENSSL_PUBLIC_DER="$WORKDIR/openssl-cert-public.der"
PUBLIC_PEM="$WORKDIR/factory-public.pem"
INPUT="$WORKDIR/provider-input.txt"
SIGNATURE="$WORKDIR/provider-signature.bin"
PROVIDER_LOG="$WORKDIR/provider-sign.log"

echo "workdir: $WORKDIR"
echo "provider port: $EX_SSS_BOOT_SSS_PORT"
echo "factory kind: $KIND"
echo "factory identity: $IDENTITY"
echo

"$SE050CTL" factory-list \
  -b "$BUS" \
  -a "$ADDRESS"

echo
"$SE050CTL" factory-cert \
  -b "$BUS" \
  -a "$ADDRESS" \
  --kind "$KIND" \
  --identity "$IDENTITY" \
  --format pem \
  --out "$CERT"

KEY_URI=$("$SE050CTL" factory-key-ref \
  --kind "$KIND" \
  --identity "$IDENTITY")
echo "key URI: $KEY_URI"

"$SE050CTL" factory-pubkey \
  -b "$BUS" \
  -a "$ADDRESS" \
  --kind "$KIND" \
  --identity "$IDENTITY" \
  --format spki-der \
  --out "$PUBLIC_DER"

openssl x509 \
  -in "$CERT" \
  -noout \
  -subject \
  -issuer \
  -serial \
  -dates

openssl x509 -in "$CERT" -pubkey -noout | \
  openssl pkey -pubin -outform DER -out "$OPENSSL_PUBLIC_DER"

cmp "$PUBLIC_DER" "$OPENSSL_PUBLIC_DER"
echo "certificate public-key extraction: OK"

openssl x509 -in "$CERT" -pubkey -noout > "$PUBLIC_PEM"
printf 'SE050 factory identity provider test\n' > "$INPUT"

openssl pkeyutl \
  -provider "$PROVIDER" \
  -provider default \
  -inkey "$KEY_URI" \
  -sign \
  -rawin \
  -digest sha256 \
  -in "$INPUT" \
  -out "$SIGNATURE" \
  2> >(tee "$PROVIDER_LOG" >&2)

openssl pkeyutl \
  -provider default \
  -pubin \
  -inkey "$PUBLIC_PEM" \
  -verify \
  -rawin \
  -digest sha256 \
  -in "$INPUT" \
  -sigfile "$SIGNATURE"

echo "factory private key matches certificate: OK"

if openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1; then
  echo "certificate time validity: currently valid"
else
  echo "certificate time validity: expired or not currently valid (informational)"
fi

echo "certificate: $CERT"
echo "certificate public key: $PUBLIC_DER"
echo "provider signature: $SIGNATURE"
echo "provider log: $PROVIDER_LOG"
echo "factory identity test: PASS"
