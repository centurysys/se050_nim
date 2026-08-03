# se050_nim

A lightweight Nim library, diagnostic CLI, and Attestation-backed kitting CSV exporter for NXP SE050 secure elements over T=1 over I2C.

The project avoids the NXP Plug & Trust Middleware and talks to the SE050 directly from embedded Linux. It now provides not only low-level primitives, but also NXP attestation certificate validation, kitting records and CSV handling, offline verification, live-device matching, and X.509/mTLS TLS client identity management. Actual OpenSSL/TLS integration uses the official NXP `se05x-openssl-provider`. Firmware-envelope formats, HKDF/AES-GCM processing, and firmware update logic belong to higher-level projects.

## Current status

The main paths verified with SE050 Applet 7.2.x devices include:

- UID read from object `0x7FFF0206`
- Applet version/config readout
- random byte generation
- Secure Object exists/type/size/list/delete helpers
- development EC key generation and public-key readout
- P-256 ECDH shared-secret derivation
- use of the NXP pre-provisioned attestation key and device certificate
- ReadObject-with-Attestation capture and ECDSA verification
- X.509 chain validation to the NXP Root and Intermediate CAs
- creation and reuse of test firmware KEX object `0x30000100`
- generation, append, and idempotent reuse of a multi-device attested CSV
- offline cryptographic verification of CSV records
- live comparison with the board serial, SE050 UID, object type, persistence, and public key
- P-256 ECDSA/SHA-256 signing
- TLS client identities managed as `identity N + A/B slot`
- attested validation of TLS identity origin, policy, and public key
- direct use of existing SE050 keys through NXP OpenSSL Provider 1.1.5 `nxp:0x...` URIs
- PKCS#10 CSR generation with the SE050 private key and CSR self-signature verification
- byte-for-byte comparison of the CSR public key with the SE050 public key
- TLS 1.2 and TLS 1.3 mutual-TLS client authentication with OpenSSL 3.5.6 and NXP Provider 1.1.5

The production creation path for `0x20000100` is implemented, but its irreversible hardware test is still pending.

The main firmware-envelope key-agreement path is:

```text
P-256 ECDH + HKDF-SHA256 + AES-256-GCM
```

X25519 key generation and public-key export worked on the tested Applet 7.2.0 path, but `ECDHGenerateSharedSecret` consistently returned `SW=0x6985`. P-256 therefore remains the supported product path.

## TLS client identity

TLS client identities are cloud-neutral P-256 client-signing keys. Each identity has A/B slots so certificates and keys can be rotated independently for multiple services.

```text
identity 0: slot A / slot B
identity 1: slot A / slot B
identity 2: slot A / slot B
...
```

Object IDs follow a fixed mapping:

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

The TLS key policy is `SIGN + READ + DELETE` (`0x10240000`). Private keys are generated inside the SE050 and are never exported to the filesystem or cloud. Existing objects are accepted only after NXP Attestation validates the type, internal origin, policy, and public key; mismatched objects are not automatically deleted or replaced.

Typical CLI usage:

```sh
se050ctl tls-keygen \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A

se050ctl tls-key-info \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A

se050ctl tls-key-ref \
  --profile test \
  --identity 0 \
  --slot A
```

`tls-key-ref` returns an NXP Provider URI such as `nxp:0x30000200`.

Hardware testing has verified ECDSA signing, PKCS#10 CSR generation and verification, and TLS 1.2 / TLS 1.3 mutual-TLS client authentication through the NXP OpenSSL Provider using an SE050-resident private key. The local mTLS test also verifies that a connection without a client certificate is rejected.

AWS IoT Core and Azure IoT Hub have been checked against their current official X.509/mTLS requirements, and provisioning/connection procedures are documented. This repository has not yet performed a live connection using actual AWS or Azure accounts.

The Host OS is treated as a trusted environment and direct I2C uses a Plain session. The design goal is TLS private-key non-exportability; preventing SE050 misuse after Host OS compromise is outside this security boundary.

Details:

- [`docs/openssl-provider.md`](docs/openssl-provider.md): NXP OpenSSL Provider integration
- [`docs/local-mtls-test.md`](docs/local-mtls-test.md): local mTLS integration test
- [`docs/aws-iot.md`](docs/aws-iot.md): AWS IoT Core provisioning and connection
- [`docs/azure-iot.md`](docs/azure-iot.md): Azure IoT Hub provisioning and connection

## Built commands

`nimble build` produces two executables:

```text
bin/se050ctl
bin/se050-kitting-export
```

- `se050ctl`: development, diagnostics, and local CSV/device verification
- `se050-kitting-export`: factory/development generation of attested CSV records

The exporter implements both the deletable `test` profile and the no-delete/no-overwrite `production` profile. Because production creation is irreversible, treat that path as experimental until it has been exercised on a non-shipping evaluation device.

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
- [`docs/local-mtls-test.md`](docs/local-mtls-test.md): local TLS 1.2/1.3 mTLS integration test
- [`docs/aws-iot.md`](docs/aws-iot.md): AWS IoT Core provisioning and connection
- [`docs/azure-iot.md`](docs/azure-iot.md): Azure IoT Hub provisioning and connection

## License

MIT License
