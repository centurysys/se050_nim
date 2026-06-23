# se050_nim examples

This directory contains small executable examples for the `se050_nim` library.
They are intended to show direct library usage, not to replace `se050ctl`.

## Build

From the repository root:

```sh
nim c examples/read_uid.nim
nim c examples/random_bytes.nim
nim c examples/object_info.nim
nim c examples/p256_keygen_pubkey.nim
nim c examples/p256_derive_secret.nim
nim c examples/p256_keygen_explicit_policy.nim
```

The existing `examples/config.nims` adds `../src` to the Nim module search path.

## Examples

```sh
# Read the SE050 unique ID from /dev/i2c-0
./examples/read_uid 0

# Generate 32 random bytes
./examples/random_bytes 0 32

# Inspect the built-in UID object
./examples/object_info 0 0x7FFF0206

# Generate one P-256 development key pair at dev index 0x110 and export its public key
./examples/p256_keygen_pubkey 0 0x110 p256_110_pub.bin

# Generate or reuse two P-256 development key pairs and verify ECDH both ways
./examples/p256_derive_secret 0 0x110 0x111

# Generate one P-256 key pair while passing an EC key policy explicitly
./examples/p256_keygen_explicit_policy 0 0x120 development p256_120_pub.bin
```

## Explicit policy example

`p256_keygen_explicit_policy.nim` demonstrates the policy-aware key generation
API. By default, use the `development` policy so the object remains removable
by `se050ctl`.

The `device` and `one-time` policy modes intentionally omit WRITE, GEN, and
DELETE permissions. Objects created with those policies may not be removable by
`se050ctl`, even in the development range. The example therefore requires
`--allow-sticky` for those modes:

```sh
./examples/p256_keygen_explicit_policy 0 0x121 device p256_121_pub.bin --allow-sticky
```

Use sticky policy modes only with disposable development object IDs.

## Safety policy

Write examples use only the development object range:

```text
0x30000000..0x3000FFFF
```

They do not write vendor, customer, NXP, or internal object ranges.
Production provisioning should be implemented in a separate tool with its own
one-time/no-delete policy handling.

## X25519

X25519 key generation and public key export may work on the tested applet, but
X25519 derive was not verified successfully on the tested SE050 applet 7.2.0
path. These examples therefore focus on P-256 ECDH, which has been verified.
