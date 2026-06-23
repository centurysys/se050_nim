# se050_nim API Guide

This guide describes the library-facing API of `se050_nim`.

`se050_nim` is intentionally a low-level SE050 primitive library. It provides the transport, APDU/TLV helpers, UID/random/object/key primitives, and P-256 ECDH. Firmware envelope handling, production provisioning policy, and updater behavior should live in higher-level projects that depend on this library.

## Module entry point

Most users should import the top-level module:

```nim
import se050_nim
```

The top-level module re-exports the lower-level modules:

- `errors`
- `transport`
- `apdu`
- `tlv`
- `uid`
- `random`
- `objects`
- `keys`
- `management`

Use direct submodule imports only when a project intentionally wants a narrower dependency.

## Result style

The library returns `SE[T]` instead of raising exceptions for normal SE050/APDU failures.

```nim
type SE[T] = object
  ok*: bool
  value*: T        # present when T is not void
  error*: Se050Error
```

Typical handling pattern:

```nim
let r = se.readUidHex()
if not r.ok:
  echo r.error.errorMessage()
  quit 1

echo r.value
```

`Se050Error.sw` is non-zero when the error came from an APDU status word such as `0x6985`.

## Opening the device

```nim
let se = openSe050(bus = 0)
```

The default I2C address is `0x48`.

```nim
let se = openSe050(bus = 0, address = 0x48'u8)
```

For APDU/T=1-over-I2C frame tracing:

```nim
let se = openSe050(bus = 0, debug = true)
```

Most high-level helpers select the SE050 applet by default via `selectFirst = true`. When issuing multiple commands in a tight sequence, callers may select once and pass `selectFirst = false` to later calls.

```nim
let selected = se.selectApplet()
if not selected.ok:
  echo selected.error.errorMessage()
  quit 1

let uid = se.readUidHex(selectFirst = false)
```

## UID

```nim
let uid = se.readUidHex()
```

Relevant APIs:

- `readUidRaw(se, selectFirst = true): SE[array[Se050UidLength, uint8]]`
- `readUidHex(se, separator = "", selectFirst = true): SE[string]`
- `uidToHex(uid, separator = ""): string`

The known UID Secure Object ID is exported as:

```nim
Se050UniqueIdObjectId = 0x7FFF0206'u32
```

## Random bytes

```nim
let rnd = se.getRandomBytes(length = 32)
```

Relevant APIs:

- `getRandomBytes(se, length, selectFirst = true): SE[seq[uint8]]`
- `getRandomHex(se, length, separator = "", selectFirst = true): SE[string]`
- `Se050MaxRandomLength = 255`
- `bytesToHex(data, separator = ""): string`

The current implementation sends one APDU and therefore accepts lengths from 1 to 255 bytes.

## Version and applet features

```nim
let info = se.getVersionInfo()
if info.ok:
  echo info.value.major, ".", info.value.minor, ".", info.value.patch
```

Relevant APIs:

- `getVersionInfo(se, selectFirst = true): SE[Se050VersionInfo]`
- `hasFeature(info, bit): bool`
- `featureName(bit): string`
- `knownFeatureBits(): seq[uint16]`

Feature constants include:

- `ConfigEcdsaEcdhEcdhe`
- `ConfigEddsa`
- `ConfigDhMont`
- `ConfigAes`
- `ConfigFipsModeDisabled`

## Secure Object inspection

```nim
let exists = se.objectExists(0x30000100'u32)
```

Relevant APIs:

- `objectExists(se, objectId, selectFirst = true): SE[bool]`
- `readObjectType(se, objectId, selectFirst = true): SE[ObjectTypeInfo]`
- `readObjectSize(se, objectId, selectFirst = true): SE[uint32]`
- `readObjectIdListChunk(se, offset = 0, filter = SecureObjectTypeAll, selectFirst = true): SE[ObjectIdListChunk]`
- `listObjectIds(se, filter = SecureObjectTypeAll, selectFirst = true): SE[seq[uint32]]`
- `objectTypeName(objectType): string`
- `transientIndicatorName(value): string`

`deleteSecureObject` is also exported, but it is intentionally a raw primitive. Safety policy such as refusing to delete non-development objects must be enforced by the CLI or provisioning tool.

## Key generation

```nim
let created = se.generateP256KeyPair(0x30000100'u32)
```

Relevant APIs:

- `generateEcKeyPair(se, objectId, curve, selectFirst = true): SE[void]`
- `generateEcKeyPair(se, objectId, curve, policy, selectFirst = true): SE[void]`
- `generateP256KeyPair(se, objectId, selectFirst = true): SE[void]`
- `generateP256KeyPair(se, objectId, policy, selectFirst = true): SE[void]`
- `generateX25519KeyPair(se, objectId, selectFirst = true): SE[void]`
- `generateX25519KeyPair(se, objectId, policy, selectFirst = true): SE[void]`
- `curveId(curve): uint8`
- `curveName(curve): string`
- `expectedKeyPairType(curve): uint8`

Supported curve enum values:

- `ecCurveP256`
- `ecCurveX25519`

The policy-free key generation helpers keep the historical behavior: they use the development EC key policy. This policy allows key agreement, public-key read, write/generate during development iteration, and delete.

Higher-level provisioning and kitting tools can pass an explicit `EcKeyPolicy` to create keys with production-style permissions. `se050ctl` intentionally does not expose these production policy controls.

## EC key policy API

`EcKeyPolicy` represents the SE050 EC key policy header used when creating EC key objects.

```nim
type
  EcKeyPolicy* = object
    header*: uint32
```

Policy builder APIs:

- `developmentEcKeyPolicy(): EcKeyPolicy`
- `deviceEcKeyPolicy(): EcKeyPolicy`
- `oneTimeDeviceKeyPolicy(): EcKeyPolicy`
- `customEcKeyPolicy(header): EcKeyPolicy`
- `policyHeader(policy): uint32`

Typical development usage:

```nim
let policy = developmentEcKeyPolicy()
let r = se.generateP256KeyPair(0x30000120'u32, policy)
```

Typical provisioning-tool usage:

```nim
let policy = oneTimeDeviceKeyPolicy()
let r = se.generateP256KeyPair(0x20000100'u32, policy)
```

The library accepts the caller-provided object ID. It does not enforce the `dev` range for raw key-generation primitives, because production kitting tools must intentionally write to `customer` or `vendor` ranges. User-facing tools must enforce their own safety policy.

Current predefined policies:

| Policy | Intended use | Allows | Intentionally avoids |
| --- | --- | --- | --- |
| `developmentEcKeyPolicy()` | development and diagnostics | key agreement, public-key read, write/generate, delete | production finalization |
| `deviceEcKeyPolicy()` | provisioned device key | key agreement, public-key read | write/generate/delete |
| `oneTimeDeviceKeyPolicy()` | final device key creation | same effective permissions as `deviceEcKeyPolicy()` for now | write/generate/delete |
| `customEcKeyPolicy(header)` | advanced callers | caller-defined | no validation beyond the raw header |

`oneTimeDeviceKeyPolicy()` is kept separate from `deviceEcKeyPolicy()` so that kitting code can express provisioning intent clearly and so the library can later adopt any applet-specific one-time encoding without changing caller code.

Be careful when testing sticky policies. If a policy does not allow delete or overwrite, the object may remain on the SE050 until the chip is reset/provisioned by another authorized path. Test production-style policies first in a reserved development object ID.

## Public key export

```nim
let pub = se.readPublicKey(0x30000100'u32)
```

Relevant API:

- `readPublicKey(se, objectId, selectFirst = true): SE[seq[uint8]]`

Observed public key sizes:

- P-256: 65 bytes, uncompressed `0x04 || X(32) || Y(32)`
- X25519: 32 bytes

## P-256 ECDH derive

```nim
let secret = se.deriveSharedSecret(
  objectId = 0x30000100'u32,
  peerPublicKey = peerPublicKeyBytes
)
```

Relevant API:

- `deriveSharedSecret(se, objectId, peerPublicKey, selectFirst = true): SE[seq[uint8]]`

For the firmware-envelope direction, use P-256 ECDH as the practical SE050-backed key agreement path. Feed the returned 32-byte shared secret into HKDF in the higher-level envelope library; do not use the raw ECDH output directly as an AES key.

X25519 key generation and public key export work on the tested applet path, but X25519 derive returned `SW=0x6985` across the tested peer-public-key encodings. Treat X25519 derive as unsupported for the current product path unless a separate applet/middleware path proves otherwise.

## Error reporting helper

```nim
if r.isErr:
  echo r.error.errorMessage()
```

Useful APIs:

- `isOk(r)`
- `isErr(r)`
- `errorMessage(e)`

## Recommended layering

Keep the responsibility boundary clear:

```text
se050_nim:
  SE050 primitive operations

se050ctl:
  development and diagnostics

se050-provision / se050-kitting:
  production object creation and policy

fwkeys / fw-envelope:
  P-256 ECDH + HKDF + AES-GCM envelope handling

fw-update:
  firmware verification, decrypt/apply, A/B switching
```
