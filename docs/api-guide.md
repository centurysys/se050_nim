# se050_nim API Guide

`se050_nim` provides SE050 primitives, attestation verification, and reusable kitting record/CSV verification. Firmware-envelope formats, HKDF/AES-GCM, and firmware updating remain in higher-level projects.

## Entry point

```nim
import se050_nim
```

The top-level module re-exports:

- transport, APDU/TLV, UID, random, objects, keys, and management;
- attestation certificate and ReadObject-with-Attestation support;
- OpenSSL crypto/X.509 verification and the embedded trust store;
- board identity, kitting profiles, records, and CSV;
- offline verification, local-device verification, and exporter merge helpers.

## Result handling

Normal failures return `SE[T]` rather than raising exceptions.

```nim
let r = se.readUidHex()
if not r.ok:
  echo r.error.errorMessage()
  quit 1
```

A non-zero `Se050Error.sw` is an APDU status word.

## Device primitives

```nim
let se = openSe050(bus = 0, address = 0x48'u8, debug = false)
let atr = se.requestAtr()
let uid = se.readUidRaw()
let random = se.getRandomBytes(32)
```

Key APIs include `selectApplet`, `requestAtr`, UID/random/version helpers, object existence/type/size/list helpers, and `deleteSecureObject`.

Raw APIs do not apply the diagnostic CLI's development-range guard. Higher-level tools must enforce Object ID policy.

## EC keys

```nim
let created = se.generateP256KeyPair(
  0x30000120'u32,
  developmentEcKeyPolicy()
)
let publicKey = se.readPublicKey(0x30000120'u32)
let secret = se.deriveSharedSecret(0x30000120'u32, peerPublicKey)
```

| Policy helper | Header | Purpose |
|---|---:|---|
| `developmentEcKeyPolicy()` | `0x043C0000` | generic development |
| `testDeviceKeyPolicy()` | `0x04240000` | deletable production-like test |
| `deviceEcKeyPolicy()` | `0x04200000` | provisioned device key |
| `oneTimeDeviceKeyPolicy()` | `0x04200000` | explicit one-time intent |
| `customEcKeyPolicy()` | caller-defined | advanced use |

P-256 public keys are 65 bytes and shared secrets are 32 bytes.

## Attestation certificate

```nim
let cert = se.readAttestationCertificate()
```

APIs:

- `readAttestationCertificate()`
- `extractAttestationCertificateDer()`
- `validateAttestationCertificateDer()`

The full BinaryFile at `0xF0000013` is read, the leading DER SEQUENCE is returned, a zero-filled tail is accepted, and non-zero trailing data is rejected.

## ReadObject-with-Attestation

```nim
let attested = se.readObjectWithAttestation(
  objectId = 0x30000100'u32,
  freshness = freshness
)
```

APIs include `buildReadObjectWithAttestationRequest`, `parseReadObjectWithAttestationResponse`, and `readObjectWithAttestation`. `AttestedObjectRead` preserves the signed command, transmitted APDU, raw response, object data, attributes, chip UID, timestamp, and signature.

## OpenSSL verification

OpenSSL 3 `libcrypto.so.3` is loaded dynamically at runtime.

Important APIs:

- `sha256()` and `certificateSha256()`
- `extractCertificateEcPublicKey()`
- `verifyEcdsaSha256WithCertificate()`
- `verifyCertificateChain()`
- DER bundle split/read helpers

OpenSSL headers and a development symlink are not required.

## Embedded NXP trust store

```nim
let roots = nxpAttestationTrustAnchors()
let intermediates = nxpAttestationIntermediates()
```

The Root and Intermediate DER files are embedded from `src/se050_nim/certs/` with `staticRead()`.

## Attestation semantics

```nim
let signature = verifyAttestationSignature(attested, cert)
let semantics = verifyKittingAttestationSemantics(
  attested,
  testKittingProfile()
)
```

Semantic verification checks the configured Object ID, attestation key ID, algorithm, complete uncompressed P-256 key, chip UID, timestamp, private-key size, key-pair type, internal origin, authentication fields, and exact policy header.

Complete certificate-chain and signature verification before trusting semantics.

## Board identity and profiles

```nim
let serial = readBoardSerialNumber()
let testProfile = testKittingProfile()
let productionProfile = productionKittingProfile()
```

The default board serial path is `/proc/device-tree/board/serialno`. Profile helpers resolve names and Object IDs and expose the expected policy and type.

## Kitting records and freshness

```nim
let freshness = deriveKittingFreshness(
  serialNumber,
  createdAt,
  testProfile,
  nonce
)
```

Important APIs:

- `validateKittingTimestamp()`
- `deriveKittingFreshness()`
- `createKittingRecord()`
- attestation container encode/decode/restore helpers

`KittingRecord` stores the board serial, version, profile, UTC timestamp, role, SE050 UID, Object ID, nonce, public key, device certificate, and captured attestation container.

## CSV

```nim
let text = encodeKittingCsv(records)
let records = decodeKittingCsv(text)
let one = findKittingRecord(records.value, serialNumber, kpTest)
```

Binary fields use strict Base64. Selection requires exactly one matching serial/profile/key-role record.

## Offline verification

```nim
let verified = verifyKittingCsvRecord(
  csvText = csvText,
  serialNumber = "11900000015",
  profileKind = kpTest,
  trustAnchorsDer = nxpAttestationTrustAnchors(),
  intermediatesDer = nxpAttestationIntermediates()
)
```

`verifyKittingRecord()` and `verifyKittingCsvRecord()` do not access I2C. They restore metadata-bound freshness, validate the certificate chain, verify the ECDSA signature, and enforce signed object semantics. They can be reused by future PC importers and database registration tools.

## Local-device verification

`verifyLocalKittingIdentity()` compares an offline-verified record with the current board serial, SE050 UID, P-256 object type, persistent indicator, and public key. Live I2C reads remain in the caller, keeping this comparison pure and unit-testable.

## Exporter merge helpers

- `sameKittingRecordKey()`
- `sameKittingDeviceKey()`
- `mergeKittingRecord()`

A record with the same serial/profile/role but a different UID, Object ID, or public key is a conflict and is never overwritten.

## Recommended layering

```text
se050_nim:
  SE050 primitives + attestation + reusable kitting verification

se050ctl:
  development/diagnostic CLI + local kitting verification

se050-kitting-export:
  current test factory exporter

future production kitting:
  irreversible customer-range key creation

fwkeys / fw-envelope:
  P-256 ECDH + HKDF + AES-GCM envelope

fw-update:
  firmware verification, decryption, and A/B update
```
