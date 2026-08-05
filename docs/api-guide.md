# se050_nim API guide

`se050_nim` provides SE050 primitives, attestation, managed TLS identities, external-key import, OpenSSL Reference Keys, and reusable kitting/CSV verification. Firmware envelope formatting, HKDF/AES-GCM, and firmware update logic remain in higher-level projects.

## Entry point

```nim
import se050_nim
```

Top-level exports:

```text
errors, transport, apdu, tlv
uid, random, objects, keys, management
binary_encoding, crypto_verify, x509_verify
factory_identity, attestation, tls, kitting
```

The `tls` facade exports `profile`, `live_identity`, `attestation_verify`, `external_key`, `openssl`, `reference_key`, and `reference_key_file`.

## Results

Runtime failures normally use `SE[T]`. A non-zero `Se050Error.sw` indicates an APDU status-word failure. Some pure host-side encoders/validators use `ValueError` for invalid caller input.

## Transport / device primitives

```nim
let se = openSe050(bus = 0, address = 0x48'u8, debug = false)
discard se.requestAtr()
```

Key APIs include applet selection/ATR, UID, random, version info, object exists/type/size/list, and raw delete. Raw library APIs do not enforce the CLI's Object-range mutation guards.

## EC keys

Managed curve enum values currently include P-256, X25519, and P-384.

Low-level operations include:

```nim
se.generateP256KeyPair(objectId, policy)
se.importP256KeyPair(objectId, privateScalar, publicKey, policy)
se.importP384KeyPair(objectId, privateScalar, publicKey, policy)
se.readPublicKey(objectId)
se.deriveSharedSecret(objectId, peerPublicKey)
```

P-256 scalar/public-point lengths are 32/65 bytes; P-384 lengths are 48/97 bytes. The low-level import functions do not enforce managed-slot ownership, certificate matching, curve state, or origin semantics; use the managed TLS import APIs for TLS identities.

## Sensitive memory and transport

`secureZero()` clears mutable strings/sequences/fixed arrays using a volatile write loop. ECDH and external-key import use a sensitive transport path that redacts raw T=1 TX/RX frames and clears temporary secret/APDU buffers.

## EC curve management

Read-only state helpers include `readEcCurveList()`, `ecCurveSetState()`, and `isEcCurveInstantiated()`.

P-384 provisioning helpers include Create/Set/Delete APDU builders, `buildNistP384ProvisioningApdus()`, and `provisionNistP384Curve()`. Provisioning uses the fixed standard secp384r1 A/B/G/N/PRIME parameters, is idempotent when already set, and performs best-effort rollback after a confirmed create if later setup/verification fails.

## TLS identity profiles

```nim
let p256 = testTlsIdentityProfile(0'u16, tisSlotA)
let p384 = testTlsIdentityProfile(0'u16, tisSlotB, ecCurveP384)
```

The Object ID depends on profile/identity/slot, not curve:

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
```

P-256 and P-384 are valid managed TLS curves. Policy is `0x10240000` (`SIGN + READ + DELETE`).

## Internal vs imported identity validation

- `inspectTlsIdentity()` requires `origin = internal`
- `inspectImportedTlsIdentity()` requires `origin = external`
- corresponding attestation-semantic validators preserve the same split

Validation is curve-aware and checks expected key-pair type, private size, public-point length, persistence, Object ID, policy, attestation chain/signature, and live/attested public-key equality.

## External private-key parsing and import

`tls/external_key.nim` uses OpenSSL 3 decoding to finish host-side validation before any SE050 mutation.

Public APIs include:

- `parseEcPrivateKey()` (recognizes P-256/P-384/P-521 and returns public metadata)
- `parseP256PrivateKey()` / `parseP384PrivateKey()`
- P-256/P-384 private-key/certificate match validators
- `importP256TlsIdentity()` / `importP384TlsIdentity()`

Public parse results expose curve/bits/group/public point/SPKI only; private scalars are kept internal to the import workflow and cleared after use.

Managed import order:

```text
profile validation
-> private-key decode/curve validation
-> certificate/public-key match
-> P-384 curve-state check
-> target-slot empty check
-> private-scalar extraction
-> sensitive WriteECKey
-> imported-origin attestation validation
-> source/live public-key equality
```

Existing objects are never overwritten. A newly created object may be best-effort rolled back if post-write validation fails.

## OpenSSL public-key helpers

- `p256PublicKeyToSpkiDer()`
- `p384PublicKeyToSpkiDer()`
- `ecPublicKeyToSpkiDer()`
- `opensslProviderKeyUri()`

## NXP Reference Keys

Pure encoders:

- `encodeP256ReferenceKeyDer()` / `encodeP256ReferenceKeyPem()`
- `encodeP384ReferenceKeyDer()` / `encodeP384ReferenceKeyPem()`

No real private scalar is included. The SEC1 privateKey field contains the key-width-sized NXP object reference.

File APIs:

- `writeP256ReferenceKeyFile()` / `writeP384ReferenceKeyFile()`
- `writeTlsReferenceKeyFile()` for internal origin
- `writeImportedTlsReferenceKeyFile()` for external origin

Files are written only after live validation, with 0600 permissions, atomic publication, and no overwrite.

## OpenSSL host verification

OpenSSL 3 `libcrypto.so.3` is loaded dynamically. Shared bindings live in `openssl_ffi.nim` and cover SHA-256, ECDSA verification, X.509 parsing/chain validation, public-key extraction/comparison, and `OSSL_DECODER` private-key decoding.

## Attestation and trust store

The library reads the NXP device attestation certificate, performs ReadObject-with-Attestation, verifies certificate chains/signatures, and then validates signed semantics such as Object ID/type/origin/policy. Embedded NXP Root/Intermediate certificates are used by the kitting/TLS verification layers.

## Kitting

Kitting remains based on the P-256 firmware-KEX profile. Reusable layers cover board serial/profile, freshness, attested records, CSV encode/decode, offline verification, local live-device comparison, and safe record merging.

## Recommended layering

```text
se050_nim:
  SE050 primitives + attestation
  + managed TLS identity / external-key import
  + OpenSSL Reference Keys
  + reusable kitting verification

se050ctl:
  diagnostics / explicit provisioning
  + curve state/provisioning
  + TLS import/reference-key tooling

NXP OpenSSL Provider:
  OpenSSL runtime -> SE050 private-key operation boundary

ordinary application:
  normal certificate/key/CA filenames only
```
