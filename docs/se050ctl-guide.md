# se050ctl Guide

`se050ctl` is the development and diagnostic CLI for `se050_nim`.

It intentionally stays in the low-level SE050 primitive layer. Production provisioning, firmware envelopes, and firmware updater behavior should be implemented by higher-level tools that depend on `se050_nim`.

## Scope

`se050ctl` is intended for:

- checking SE050 connectivity
- reading UID
- generating random bytes
- reading applet version/features
- listing and inspecting Secure Objects
- creating development EC key pairs
- exporting public keys
- deriving P-256 shared secrets for diagnostics
- deleting development objects

It is not intended for:

- production one-time/no-delete provisioning
- customer/vendor object policy management
- firmware envelope parsing
- firmware decryption/apply logic
- updater A/B switching

## Common options

Most commands accept:

```text
-b, --bus       I2C bus number, for example 0 for /dev/i2c-0
-a, --address   SE050 I2C address, default 0x48
-d, --debug     print T=1 over I2C frames
```

Example:

```sh
./se050ctl uid -b 0
```

## Object references

Commands that target an SE050 Secure Object accept exactly one of these forms:

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

These forms are mutually exclusive.

`--area` names are:

- `vendor`
- `customer`
- `dev`
- `nxp`
- `internal`

`--index` is relative to the area base. Decimal values are accepted by default, and `0x`-prefixed values are accepted as hexadecimal.

Example:

```sh
./se050ctl info -b 0 --area dev --index 0x100
```

This resolves to object ID `0x30000100`.

## UID

Read the unique ID object:

```sh
./se050ctl uid -b 0
```

Colon-separated output:

```sh
./se050ctl uid -b 0 --colon
```

The known UID object name can also be used with object commands:

```sh
./se050ctl info -b 0 --name uid
```

## Random

Generate random bytes:

```sh
./se050ctl random -b 0 --len 32
```

Colon-separated output:

```sh
./se050ctl random -b 0 --len 32 --colon
```

The supported length range is 1..255 bytes.

## Version

Read applet version and feature bitmap:

```sh
./se050ctl version -b 0
```

The output includes applet version, applet config, secure box version, and feature flags such as `ECDSA_ECDH_ECDHE`, `DH_MONT`, `AES`, and `FIPS_MODE_DISABLED`.

## Exists

Check whether an object exists:

```sh
./se050ctl exists -b 0 --area dev --index 0x100
```

Quiet mode returns only the exit code:

```sh
./se050ctl exists -b 0 --area dev --index 0x100 --quiet
```

## Info

Inspect object type, persistence, and size:

```sh
./se050ctl info -b 0 --area dev --index 0x100
```

Example output for a P-256 key pair:

```text
id: 0x30000100
ref: area:dev[0x00000100]
area: dev
exists: yes
type: 0x29 (EC_KEY_PAIR_NIST_P256)
transient: 0x01 (persistent)
size: 32
```

## List

List visible object IDs:

```sh
./se050ctl list -b 0
```

List only development objects:

```sh
./se050ctl list -b 0 --area dev
```

Add area/name annotations:

```sh
./se050ctl list -b 0 --annotate
```

Filter by raw SecureObjectType byte:

```sh
./se050ctl list -b 0 --filter 0x29
```

`0xFF` means all object types.

## Key generation

Create a development P-256 key pair:

```sh
./se050ctl keygen -b 0 --area dev --index 0x100
```

The default curve is P-256.

Explicit P-256:

```sh
./se050ctl keygen -b 0 --area dev --index 0x100 --curve p256
```

X25519 key generation is supported for diagnostics:

```sh
./se050ctl keygen -b 0 --area dev --index 0x120 --curve x25519
```

However, X25519 derive is not the product path on the tested applet because `ECDHGenerateSharedSecret` returned `SW=0x6985` across the tested encodings.

`se050ctl keygen` intentionally allows only the `dev` range. Production keys in vendor/customer ranges should be created by a dedicated provisioning tool.

## Public key export

Write the raw public key to a file:

```sh
./se050ctl pubkey -b 0 --area dev --index 0x100 --out p256_pub.bin
```

Print as hex:

```sh
./se050ctl pubkey -b 0 --area dev --index 0x100
```

P-256 public keys are 65-byte uncompressed points:

```text
0x04 || X(32) || Y(32)
```

X25519 public keys are 32 bytes.

## P-256 derive

Given two P-256 key pairs:

```sh
./se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
./se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

./se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
./se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin
```

Derive A private × B public:

```sh
./se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin
```

Derive B private × A public:

```sh
./se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin
```

Verify both sides match:

```sh
sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

The shared secret should be 32 bytes. Higher-level firmware envelope code should feed it into HKDF instead of using it directly as an AES key.

## Delete

Delete a development object:

```sh
./se050ctl delete -b 0 --area dev --index 0x100
```

Deletion is refused outside the development range. This guard is intentional. Production object deletion and production policy management should not be part of the diagnostic CLI.

## Recommended smoke test

```sh
./se050ctl version -b 0
./se050ctl random -b 0 --len 32
./se050ctl list -b 0 --area dev --annotate

./se050ctl delete -b 0 --area dev --index 0x110 || true
./se050ctl delete -b 0 --area dev --index 0x111 || true

./se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
./se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

./se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
./se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin

./se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin

./se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin

ls -l p256_a_pub.bin p256_b_pub.bin p256_secret_ab.bin p256_secret_ba.bin
sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

Expected sizes:

- `p256_a_pub.bin`: 65 bytes
- `p256_b_pub.bin`: 65 bytes
- `p256_secret_ab.bin`: 32 bytes
- `p256_secret_ba.bin`: 32 bytes
