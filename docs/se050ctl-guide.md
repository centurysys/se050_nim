# se050ctl Guide

`se050ctl` is the development and diagnostic CLI for `se050_nim`. It provides SE050 primitives, TLS client identity keys, attestation diagnostics, and local comparison of a kitting CSV with the current unit. It does not create the production one-time firmware KEX key or process firmware envelopes.

## Scope

Included:

- UID, random, and Applet version/config
- Secure Object exists/info/list
- development-range EC key creation and deletion
- fixed A/B TLS client identity key creation and verification for test/production profiles
- public-key export and P-256 ECDH derive
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

## TLS client identity keys

TLS client identity commands do not accept arbitrary Object IDs. They operate only on fixed profile/slot mappings:

```text
test A        0x30000200
test B        0x30000201
production A  0x20000200
production B  0x20000201
```

All slots use `SIGN + READ + DELETE` policy `0x10240000`. Existing objects are never automatically deleted or overwritten.

### `tls-key-ref`

Prints the URI used by NXP `se05x-openssl-provider` to reference an existing SE050 key. This command does not access the SE050, so no `-b` option is required.

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200

se050ctl tls-key-ref --profile production --identity 1 --slot B
# nxp:0x20000203
```

The output can be passed directly to OpenSSL 3 `-key` / `-inkey` options.

```sh
KEY_URI=$(se050ctl tls-key-ref --profile test --identity 0 --slot A)
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default \
  -inkey "$KEY_URI" -sign -rawin -in input.txt -out signature.der -digest sha256
```

### `tls-keygen`

```sh
se050ctl tls-keygen -b 0 --profile test --identity 0 --slot A
se050ctl tls-keygen -b 0 --profile production --identity 0 --slot A
se050ctl tls-keygen -b 0 --profile production --identity 1 --slot B
```

If the slot is empty, a P-256 key pair is generated inside the SE050. If it already exists, it is not regenerated. The command validates the live type/persistence, NXP device certificate chain, attestation signature, signed Object ID/type/internal origin/policy, and the match between live and attested public keys before accepting the object. A failed post-generation check never triggers automatic deletion.

### `tls-key-info`

```sh
se050ctl tls-key-info -b 0 --profile test --identity 0 --slot A
se050ctl tls-key-info -b 0 --profile production --identity 0 --slot A
se050ctl tls-key-info -b 0 --profile production --identity 1 --slot B
```

This performs the same trust and semantic validation without changing the key, then prints its profile, slot, Object ID, public key, origin, and policy.

Generic `keygen` and `delete` still reject the customer range. Production TLS slots are writable only through the dedicated TLS command.

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
