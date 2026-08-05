# se050_nim

A lightweight Nim library, diagnostic CLI, and Attestation-backed kitting CSV exporter for NXP SE050 secure elements over T=1 over I2C.

The project avoids the NXP Plug & Trust Middleware and talks to the SE050 directly from embedded Linux. It now provides not only low-level primitives, but also NXP attestation certificate validation, kitting records and CSV handling, offline verification, live-device matching, and X.509/mTLS TLS client identity management. Actual OpenSSL/TLS integration uses the official NXP `se05x-openssl-provider`. Firmware-envelope formats, HKDF/AES-GCM processing, and firmware update logic belong to higher-level projects.

## Current status

The following paths have been verified on hardware with an SE050 Applet 7.2.x device:

- UID read from Object `0x7FFF0206`
- Applet version/configuration readout
- random generation
- Secure Object exists/type/size/list/delete helpers
- development EC key generation and public-key readout
- P-256 ECDH shared-secret derivation
- use of the NXP pre-provisioned attestation key and device certificate
- ReadObject-with-Attestation acquisition and ECDSA verification
- X.509 chain validation through the NXP Root/Intermediate certificates
- create/reuse of the test firmware KEX key at `0x30000100`
- append/retry-safe multi-device attested CSV generation
- offline cryptographic CSV verification
- local comparison of CSV data with board serial, SE050 UID, and live public key
- P-256 ECDSA/SHA-256 signing
- TLS client identity management with `identity N + A/B slot`
- strict attestation validation of internally generated P-256 TLS identities (`origin = internal`)
- parsing unencrypted external P-256/P-384 private keys, certificate/public-key matching, and import into empty managed TLS slots
- strict validation of imported TLS identities (`origin = external`)
- P-384 curve-instantiation query and transactional provisioning of the standard secp384r1 domain parameters
- NXP P-256/P-384 Reference Key DER/PEM encoding without exporting private scalars
- 0600 non-overwriting Reference Key file export after live identity validation
- redaction of sensitive import/ECDH T=1 frames and clearing of temporary secret buffers
- NXP Provider-backed ECDSA signing through both P-256 and P-384 Reference Keys
- NXP/default Provider autoload through `openssl.cnf`
- TLS 1.2 and TLS 1.3 mutual TLS from an ordinary Nim `std/net` client containing no SE050-specific application code, for both P-256 and P-384

The production firmware-KEX path at `0x20000100` is implemented, but its irreversible hardware test is still pending.

The firmware-envelope key agreement path remains:

```text
P-256 ECDH + HKDF-SHA256 + AES-256-GCM
```

X25519 key generation and public-key export succeeded on the tested Applet 7.2.0 path, but `ECDHGenerateSharedSecret` consistently returned `SW=0x6985`. The current product path therefore uses P-256 for firmware KEX.

## TLS client identities

TLS client identities are cloud-neutral X.509/mTLS client-signing keys. Each identity has A/B slots for certificate/key rotation.

```text
identity 0: slot A / slot B
identity 1: slot A / slot B
identity 2: slot A / slot B
...
```

Object IDs do not encode the curve:

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

All managed TLS slots use `SIGN + READ + DELETE` policy `0x10240000`. Because the Object ID does not distinguish P-256 from P-384, non-default curve operations carry the curve explicitly.

Two provisioning paths are currently supported:

- `tls-keygen`: generate P-256 inside the SE050 and require `origin = internal`
- `tls-key-import`: validate an external unencrypted P-256/P-384 private key and matching X.509 certificate before importing it into an empty slot, then require `origin = external`

External import never overwrites an existing object. Algorithm/curve/certificate matching is performed before the SE050 write; the resulting live type, persistence, policy, origin, and public key are validated afterward. Private-key file buffers and temporary WriteECKey buffers are cleared, and sensitive T=1 frames are redacted in debug output.

P-384 import requires the standard curve to be instantiated in the SE05x global curve state:

```sh
se050ctl curve-list -b 0
se050ctl curve-provision-p384 -b 0 --yes
```

`curve-provision-p384` changes persistent global curve state rather than a disposable key object, and therefore requires explicit confirmation.

Internal P-256 example:

```sh
se050ctl tls-keygen -b 0 --profile test --identity 0 --slot A
```

External P-384 example:

```sh
se050ctl tls-key-import \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --key client.key \
  --cert client.crt

se050ctl tls-key-info \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --imported
```

The Provider-native Object URI remains available for explicit Provider tooling:

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200
```

For **transparent use by ordinary OpenSSL/Nim TLS applications**, export a Reference Key file instead. The application sees only a normal private-key filename.

```sh
se050ctl tls-key-ref-file \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot B \
  --curve p384 \
  --imported \
  --out device.key
```

With the NXP and default Providers autoloaded through `openssl.cnf`, the Nim application remains ordinary `std/net` code:

```nim
let ctx = newContext(
  verifyMode = CVerifyPeer,
  certFile = certFile,
  keyFile = keyFile,
  caFile = caFile
)
```

P-256 and P-384 have both been verified with TLS 1.3 and TLS 1.2 mutual TLS on Athena hardware.

See the existing AWS IoT Core / Azure IoT Hub documents for cloud-specific provisioning. Service-side algorithm and curve acceptance must be checked against the current cloud service specification before selecting P-384.

The host OS is treated as trusted. Direct I2C uses a Plain session; the main boundary is private-key non-exportability, not prevention of SE050 use after host compromise.

Details:

- [`docs/openssl-provider.md`](docs/openssl-provider.md): Provider URI, Reference Keys, autoload, and transparent TLS
- [`docs/local-mtls-test.md`](docs/local-mtls-test.md): local P-256/P-384 mTLS integration tests
- [`docs/se050ctl-guide.md`](docs/se050ctl-guide.md): curve/import/reference-key CLI
- [`docs/factory-identities.md`](docs/factory-identities.md): NXP factory-provisioned cloud identities
- [`docs/aws-iot.md`](docs/aws-iot.md): AWS IoT Core provisioning/connection
- [`docs/azure-iot.md`](docs/azure-iot.md): Azure IoT Hub provisioning/connection

## NXP factory-provisioned cloud identities

Known NXP cloud connection credentials can be used read-only when they are present on the target SE050 variant. The catalog covers ECC P-256 and RSA-2048 identity 0/1 pairs; `factory-list` reports which objects actually exist.

```sh
se050ctl factory-list -b 0

se050ctl factory-cert \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --out device.crt

KEY_URI=$(se050ctl factory-key-ref --kind ecc --identity 0)
```

This path avoids new key generation, CSR generation, and private-key files. Register the factory certificate with the target service and reference the private key through the NXP OpenSSL Provider `nxp:0x...` URI.

Use the managed TLS identities for customer-controlled PKI, rotation, and multiple independent service identities. Factory-certificate validity, revocation, chain trust, and target-service acceptance must be checked for the deployment.

See [`docs/factory-identities.md`](docs/factory-identities.md).

## Kitting

The exporter reads the board serial from `/proc/device-tree/board/serialno`, creates or reuses the test key, and appends an Attestation-backed record.

```sh
se050-kitting-export test \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

The production command irreversibly creates the fixed object `0x20000100` with policy `0x04200000`.

```sh
se050-kitting-export production \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

The production path never deletes or overwrites an existing object. It stops if the existing type or signed policy is different.

A second run with the same board and key does not duplicate the row:

```text
CSV record: already valid
```

Verify the CSV against the same unit:

```sh
se050ctl kitting-verify \
  -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

The NXP Attestation Root and Intermediate certificates are embedded with `staticRead()`, so kitting commands do not accept replacement CA files.

See [`docs/kitting-guide.md`](docs/kitting-guide.md) for details.

## Common `se050ctl` options

```text
-b, --bus <n>          I2C bus number, e.g. 0 for /dev/i2c-0
-a, --address <hex>    SE050 I2C address, default: 0x48
-d, --debug            Print T=1 over I2C frames
```

Main commands:

```text
uid                 Read the UID
random              Generate random bytes
version             Inspect Applet version/config
exists/info/list    Inspect Secure Objects
keygen/pubkey       Create development EC keys and read public keys
tls-keygen           Create or validate a TLS client identity key
tls-key-info          Show an Attestation-validated TLS identity
tls-key-ref           Generate an NXP Provider `nxp:0x...` URI
tls-key-pubkey        Export raw/SPKI DER TLS identity public keys
derive              Perform P-256 ECDH
attestation-cert    Export the NXP device certificate as DER
attest-read         Diagnostic ReadObject-with-Attestation capture
attest-verify       Live attestation diagnostic with explicit CA files
kitting-verify      Embedded-CA CSV and live-device verification
delete              Delete development-range objects
```

See [`docs/se050ctl-guide.md`](docs/se050ctl-guide.md).

## Development P-256 key agreement

```sh
se050ctl delete -b 0 --area dev --index 0x110 || true
se050ctl delete -b 0 --area dev --index 0x111 || true

se050ctl keygen -b 0 --area dev --index 0x110
se050ctl keygen -b 0 --area dev --index 0x111

se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a.bin
se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b.bin

se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b.bin \
  --out p256_secret_ab.bin

se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a.bin \
  --out p256_secret_ba.bin

cmp p256_secret_ab.bin p256_secret_ba.bin
```

P-256 public keys are 65-byte uncompressed points, and ECDH shared secrets are 32 bytes.

## Object IDs and policies

| Purpose | Object ID | Policy header | Status |
|---|---:|---:|---|
| Generic development key | development range | `0x043C0000` | Created by `se050ctl keygen` |
| TLS identity test | `0x30000200 + identity * 2 + slotOffset` | `0x10240000` | Hardware-tested with identities 0 and 1 |
| TLS identity production | `0x20000200 + identity * 2 + slotOffset` | `0x10240000` | CLI/policy implemented; live cloud connection not tested |
| Test firmware KEX | `0x30000100` | `0x04240000` | Implemented and tested |
| Production firmware KEX | `0x20000100` | `0x04200000` | Exporter implemented; irreversible device test pending |
| NXP attestation key | `0xF0000012` | NXP provisioned | Used for verification |
| NXP device certificate | `0xF0000013` | NXP provisioned | Used for verification |

A key created at `0x30000100` with generic `se050ctl keygen` has the wrong policy for kitting and is rejected. After confirming that it is a disposable test object, delete it explicitly and let the exporter recreate it.

See [`docs/object-ranges.md`](docs/object-ranges.md).

## Library responsibility

`src/se050_nim.nim` re-exports these functional areas:

- transport/APDU/TLV, UID, random, Secure Object, and key management
- attestation certificate readout and ReadObject-with-Attestation
- OpenSSL 3 SHA-256, ECDSA, and X.509 verification
- embedded NXP trust store
- board identity, kitting profiles, records, and CSV handling
- offline kitting verification
- local-device identity verification
- TLS identity profiles, identity numbering, and A/B slots
- TLS identity Attestation semantic validation
- NXP OpenSSL Provider Object URIs and P-256 SPKI DER conversion
- NXP factory cloud identity catalog and certificate/public-key readout
- exporter CSV merge helpers

Firmware-envelope formats, HKDF, AES-GCM, release CEK handling, firmware signatures, and A/B updates remain out of scope.

## Build and runtime requirements

```sh
nimble build
nimble test
```

Nim dependencies:

```nim
requires "nim >= 2.2.10"
requires "results >= 0.5.1"
requires "argparse >= 4.0.2"
```

Keep `results` as `>= 0.5.1`.

The embedded trust store requires these DER files in the source tree:

```text
src/se050_nim/certs/nxp-attestation-ecc-root.der
src/se050_nim/certs/nxp-attestation-ecc-intermediate.der
```

Targets that execute attestation verification must provide OpenSSL 3 `libcrypto.so.3`. OpenSSL headers and a development symlink are not required because the library is loaded dynamically at runtime.

Using TLS client identities from OpenSSL/TLS additionally requires the official NXP `se05x-openssl-provider` `libsssProvider.so`. `se050_nim` itself remains independent of the NXP Plug & Trust Middleware; the provider is used only as the TLS runtime integration boundary.

## Documentation

- [`docs/se050ctl-guide.md`](docs/se050ctl-guide.md): CLI
- [`docs/api-guide.md`](docs/api-guide.md): library API
- [`docs/kitting-guide.md`](docs/kitting-guide.md): Attestation-backed kitting
- [`docs/object-ranges.md`](docs/object-ranges.md): Object IDs and policies
- [`docs/p256-ecdh.md`](docs/p256-ecdh.md): P-256 ECDH for envelopes
- [`docs/openssl-provider.md`](docs/openssl-provider.md): NXP OpenSSL Provider integration
- [`docs/factory-identities.md`](docs/factory-identities.md): NXP factory-provisioned cloud identities
- [`docs/local-mtls-test.md`](docs/local-mtls-test.md): local TLS 1.2/1.3 mTLS integration test
- [`docs/aws-iot.md`](docs/aws-iot.md): AWS IoT Core provisioning and connection
- [`docs/azure-iot.md`](docs/azure-iot.md): Azure IoT Hub provisioning and connection

## License

MIT License
