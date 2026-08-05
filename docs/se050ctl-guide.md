# se050ctl Guide

`se050ctl` is the development and diagnostic CLI for `se050_nim`. It provides SE050 primitives, TLS client identity keys, attestation diagnostics, and local comparison of a kitting CSV with the current unit. It does not create the production one-time firmware KEX key or process firmware envelopes.

## Scope

Included:

- UID, random, and Applet version/config
- Secure Object exists/info/list
- development-range EC key creation and deletion
- managed TLS identities by identity number + A/B slot (internal P-256 generation and external P-256/P-384 import)
- EC curve-state/P-384 provisioning, TLS public/Reference Key export, and P-256 ECDH derive
- NXP device certificate DER export
- raw ReadObject-with-Attestation capture
- live attestation diagnostics with explicit CA files
- kitting CSV and live-device verification with embedded NXP CAs

Excluded:

- production one-time/no-delete firmware KEX key creation
- general customer/vendor object writes and deletion
- a PC-only CSV verification executable
- HKDF/AES-GCM envelope processing
- firmware decryption and A/B updates

## Common options

```text
-b, --bus       I2C bus number, e.g. 0 for /dev/i2c-0
-a, --address   SE050 I2C address, default: 0x48
-d, --debug     Print T=1 over I2C frames
```

## Object references

Use exactly one form:

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

Areas are `vendor`, `customer`, `dev`, `nxp`, and `internal`.

## Basic commands

```sh
se050ctl uid -b 0
se050ctl random -b 0 --len 32
se050ctl version -b 0
se050ctl exists -b 0 --area dev --index 0x100
se050ctl info -b 0 --area dev --index 0x100
se050ctl list -b 0 --area dev --annotate
```

Random length is 1..255 bytes. `exists --quiet` uses the exit status without printing.

## NXP factory-provisioned cloud identities

When the target SE050 variant contains NXP factory cloud credentials, the CLI can export their certificates and Provider references without modifying the objects.

```sh
se050ctl factory-list -b 0

se050ctl factory-cert \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device.crt

se050ctl factory-key-ref --kind ecc --identity 0

se050ctl factory-pubkey \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device-public.pem
```

`--kind` accepts `ecc` or `rsa`; `--identity` accepts `0` or `1`. Object presence depends on the SE050 variant. These commands never create, overwrite, or delete factory objects.

See [`factory-identities.md`](factory-identities.md).

## EC curve state

```sh
se050ctl curve-list -b 0
```

The reported `set` / `not-set` state is current persistent SE05x Weierstrass curve instantiation, not silicon capability.

To explicitly provision the fixed standard NIST P-384 parameters when P-384 is not set:

```sh
se050ctl curve-provision-p384 -b 0 --yes
```

`--yes` is mandatory because this changes persistent global curve state rather than a disposable key object. An already-instantiated P-384 curve is left unchanged; failures after a confirmed create use best-effort rollback.

## TLS client identity keys

Managed TLS commands use fixed `profile / identity / slot / curve` metadata rather than arbitrary Object IDs. The Object ID does not encode the curve.

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

All slots use `SIGN + READ + DELETE` policy `0x10240000`. Existing objects are never automatically overwritten or deleted.

P-256 and P-384 are managed curves, but **`tls-keygen` internal generation is currently P-256 only**. P-384 is supported through external import.

### `tls-keygen`

```sh
se050ctl tls-keygen -b 0 --profile test --identity 0 --slot A
```

Creates or validates an internally generated P-256 identity and requires persistent P-256 key-pair type, valid NXP attestation chain/signature, `origin = internal`, policy `0x10240000`, and live/attested public-key equality. Invalid existing objects are never replaced.

### `tls-key-import`

```sh
se050ctl tls-key-import \
  -b 0 \
  --profile test --identity 0 --slot B \
  --curve p384 \
  --key client.key \
  --cert client.crt
```

`--curve` accepts `p256` or `p384` and defaults to `p256`. Private keys must be unencrypted PEM or DER; certificates may be PEM or DER.

Before writing the SE050, OpenSSL 3 validates the private key, curve/key-pair consistency, and matching X.509 certificate public key. P-384 also requires the curve to already be instantiated. The target slot must be empty.

After writing, the CLI validates `origin = external`, type/size, persistence, policy, attestation, and source/live public-key equality. Sensitive import transport is redacted and temporary private material is cleared.

### `tls-key-info`

Internal P-256:

```sh
se050ctl tls-key-info -b 0 --profile test --identity 0 --slot A
```

Imported P-384:

```sh
se050ctl tls-key-info \
  -b 0 --profile test --identity 0 --slot B \
  --curve p384 --imported
```

Without `--imported`, validation requires `origin = internal`; with it, validation requires `origin = external`. Origin is never auto-detected to weaken validation.

### `tls-key-pubkey`

```sh
se050ctl tls-key-pubkey \
  -b 0 --profile test --identity 0 --slot B \
  --curve p384 --imported \
  --format spki-der \
  --out se050-public.der
```

Raw public points are 65 bytes for P-256 and 97 bytes for P-384. SPKI DER export supports both curves.

### `tls-key-ref`

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200
```

This Provider-native URI is useful for explicit Provider diagnostics and does not access the SE050.

### `tls-key-ref-file`

Export an attestation-validated NXP Reference Key PEM for transparent normal key-file APIs.

Internal P-256:

```sh
se050ctl tls-key-ref-file \
  -b 0 --profile test --identity 0 --slot A \
  --out device.key
```

Imported P-384:

```sh
se050ctl tls-key-ref-file \
  -b 0 --profile test --identity 0 --slot B \
  --curve p384 --imported \
  --out device.key
```

The Reference Key contains no real private scalar. It is atomically installed with private-key-style 0600 permissions and existing paths are not overwritten. With NXP/default Providers autoloaded through `openssl.cnf`, an ordinary OpenSSL/Nim application can use it as a normal `keyFile`.

## Development EC keys

```sh
se050ctl keygen -b 0 --area dev --index 0x120 --curve p256
se050ctl pubkey -b 0 --area dev --index 0x120 --out p256_pub.bin
se050ctl derive -b 0 --area dev --index 0x120 \
  --peer-public peer_p256.bin \
  --out shared_secret.bin
se050ctl delete -b 0 --area dev --index 0x120
```

`keygen` is limited to the development range and uses generic development policy `0x043C0000`. A key created that way at `0x30000100` is not a valid kitting test key and is rejected by the exporter.

P-256 public keys are 65-byte uncompressed points, and shared secrets are 32 bytes. X25519 derive is refused because the tested Applet 7.2.0 path returned `SW=0x6985`.

## Attestation commands

### `attestation-cert`

Export the pre-provisioned device certificate from `0xF0000013`:

```sh
se050ctl attestation-cert -b 0 --out se050-attestation-cert.der
```

A zero-padded BinaryFile tail is removed; non-zero trailing bytes are rejected.

### `attest-read`

Capture raw ReadObject-with-Attestation data without verifying it:

```sh
se050ctl attest-read \
  -b 0 \
  --id 0x30000100 \
  --freshness 000102030405060708090A0B0C0D0E0F \
  --out-prefix /tmp/attest
```

It writes `.command.bin`, `.transmit-apdu.bin`, `.response.bin`, `.signature.bin`, and, when present, `.object.bin` files.

### `attest-verify`

Verify a live attestation using explicit external CA files:

```sh
se050ctl attest-verify \
  -b 0 \
  --id 0x30000100 \
  --freshness 000102030405060708090A0B0C0D0E0F \
  --trust-anchors nxp-attestation-ecc-root.der \
  --intermediates nxp-attestation-ecc-intermediate.der
```

This verifies the device certificate chain, the match between the certificate public key and `0xF0000012`, the ECDSA attestation signature, and the signed object semantics. External CA selection remains only for diagnostics and CA update investigations.

## `kitting-verify`

Select this board's row from a multi-device CSV, perform offline verification, and compare it with the live unit:

```sh
se050ctl kitting-verify \
  -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

It validates the CSV and freshness, the embedded NXP certificate chain, the attestation signature and semantics, the Device Tree serial, live SE050 UID, object type/persistence, and public key.

The default profile is `production`; explicitly use `--profile test` for CSV files generated by the current exporter.

## Recommended test-kitting smoke test

```sh
se050-kitting-export test -b 0 --append /tmp/se050-kitting.csv
se050-kitting-export test -b 0 --append /tmp/se050-kitting.csv
se050ctl kitting-verify -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

Expect `CSV record: added` on the first run and `CSV record: already valid` on the second.

See [`kitting-guide.md`](kitting-guide.md).
