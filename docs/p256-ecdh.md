# P-256 ECDH Notes

This document records the practical key-agreement direction for firmware-envelope work using `se050_nim`.

## Decision

Use P-256 ECDH as the SE050-backed key-agreement primitive for the firmware envelope path.

The verified path is:

```text
SE050 device P-256 private key
  x
external peer P-256 public key
  -> 32-byte ECDH shared secret
  -> HKDF-SHA256 in the higher-level envelope library
  -> AES-256-GCM wrap/open key
```

Do not use the raw ECDH shared secret directly as an AES key.

## Public key format

`readPublicKey` returns P-256 public keys as a 65-byte uncompressed point:

```text
0x04 || X(32) || Y(32)
```

This is the format expected by `se050ctl derive --peer-public` for P-256.

## Shared secret size

P-256 ECDH returns a 32-byte shared secret.

Both directions should match:

```text
A private x B public == B private x A public
```

## Smoke test

```sh
./se050ctl delete -b 0 --area dev --index 0x110 || true
./se050ctl delete -b 0 --area dev --index 0x111 || true

./se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
./se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

./se050ctl info -b 0 --area dev --index 0x110
./se050ctl info -b 0 --area dev --index 0x111

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

```text
p256_a_pub.bin        65 bytes
p256_b_pub.bin        65 bytes
p256_secret_ab.bin    32 bytes
p256_secret_ba.bin    32 bytes
```

`sha256sum` should show the same digest for both secrets, and `cmp` should succeed.

## Firmware envelope layering

`se050_nim` stops at ECDH derive. The next layer should handle:

```text
shared_secret = SE050 P-256 ECDH(device_private, server_ephemeral_public)
wrap_key      = HKDF-SHA256(shared_secret, salt, info/aad)
release_cek   = AES-256-GCM-open(wrapped_release_cek, wrap_key, nonce, aad, tag)
```

The higher-level envelope project should define:

- envelope JSON/CBOR format
- server ephemeral public key encoding
- salt/info/aad layout
- AES-GCM nonce/tag layout
- release CEK handling
- firmware body encryption/decryption
- firmware signature verification

## Suggested envelope public key field

For P-256, store the server ephemeral public key in the same uncompressed format:

```json
{
  "alg": "P256-ECDH-HKDF-SHA256+A256GCM",
  "server_ephemeral_public_format": "p256-uncompressed",
  "server_ephemeral_public": "04...",
  "salt": "...",
  "aad": "...",
  "nonce": "...",
  "wrapped_release_cek": "...",
  "tag": "..."
}
```

The envelope library should validate that the decoded public key is exactly 65 bytes and starts with `0x04` before calling `deriveSharedSecret`.

## X25519 status

X25519 was investigated because `X25519 + Ed25519` would be a clean design pair. On the tested SE050 applet path:

- X25519 key generation works
- object type is `0x69 EC_KEY_PAIR_MONT_DH_25519`
- public key export works and returns 32 bytes
- derive fails with `SW=0x6985`

Tested peer-public encodings included:

- raw 32-byte public key in `TAG_2`
- curve-prefixed `0x41 || public_key`
- nested value TLV `TAG_2 = 42 22 83 20 <public_key>`

All tested derive paths still failed with `SW=0x6985`. Therefore, X25519 derive should remain out of the product path unless a separate applet/middleware path later proves it works.

## Production note

The development keys created by `se050ctl` are intentionally deletable. Production device keys should be created by a separate provisioning/kitting tool using a production policy, likely in the `customer` range.
