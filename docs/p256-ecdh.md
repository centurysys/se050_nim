# P-256 ECDH Notes

This document records the key-agreement design for firmware envelopes built on `se050_nim`.

## Decision

Use P-256 ECDH as the SE050-backed key-agreement primitive.

```text
SE050 device P-256 private key
  x
server ephemeral P-256 public key
  -> 32-byte ECDH shared secret
  -> HKDF-SHA256
  -> AES-256-GCM wrap/open key
```

Do not use the raw ECDH shared secret directly as an AES key.

## Device key and kitting CSV

Test kitting stores the Attestation-backed public key of SE050 object `0x30000100` in the CSV. The future production profile uses `0x20000100`.

The envelope generator should obtain the device public key only from a cryptographically verified CSV or database record.

```text
board serial
  -> verified kitting record
  -> SE050 UID + device P-256 public key
  -> per-device envelope
```

Attestation binds the public key, Object ID, SE050 UID, policy, and board-serial-derived freshness. The production key creation CLI is implemented, but its irreversible hardware test is still pending. Envelope generation is not implemented yet.

## Public-key format

`readPublicKey` returns a 65-byte uncompressed P-256 point:

```text
0x04 || X(32) || Y(32)
```

`se050ctl derive --peer-public` expects the same format.

## Shared secret

The P-256 ECDH shared secret is 32 bytes.

```text
A private x B public == B private x A public
```

## Smoke test

```sh
se050ctl delete -b 0 --area dev --index 0x110 || true
se050ctl delete -b 0 --area dev --index 0x111 || true

se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin

se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin

se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin

sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

Expected sizes:

```text
public key:    65 bytes
shared secret: 32 bytes
```

## Envelope layer

`se050_nim` owns the SE050 ECDH primitive and kitting verification. A higher layer should implement:

```text
shared_secret = SE050 P-256 ECDH(device_private, server_ephemeral_public)
wrap_key      = HKDF-SHA256(shared_secret, salt, info/aad)
release_cek   = AES-256-GCM-open(wrapped_release_cek, wrap_key, nonce, aad, tag)
```

The higher-level project must define:

- envelope JSON/CBOR format;
- algorithm/version identifiers;
- server ephemeral public-key encoding;
- HKDF salt and info;
- AAD layout;
- AES-GCM nonce and tag layout;
- release CEK handling;
- firmware body encryption/decryption;
- firmware signature verification.

## Suggested public-key fields

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

Validate that the decoded server ephemeral key is exactly 65 bytes and begins with `0x04` before passing it to the SE050.

## X25519

On the tested Applet path:

- key generation succeeded;
- object type was `0x69 EC_KEY_PAIR_MONT_DH_25519`;
- 32-byte public-key export succeeded;
- derive returned `SW=0x6985`.

Raw, curve-prefixed, and nested-TLV peer encodings did not work, so X25519 remains outside the product path until another Applet or middleware path proves it.

## Production note

Only the deletable test kitting key `0x30000100` has been exercised on hardware. The irreversible production creation CLI for `0x20000100` is implemented, but it has not yet been tested on a non-shipping evaluation device.
