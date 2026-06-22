# se050_nim

Lightweight Nim library and diagnostic CLI for accessing an NXP SE050 secure element over T=1 over I2C.

The project intentionally avoids NXP Plug & Trust Middleware and exposes small SE050 primitives that are useful for embedded Linux products, firmware-envelope experiments, and production provisioning tools built on top of this library.

## Current status

Verified on the currently tested SE050 applet path:

- UID read from object `0x7FFF0206`
- SE050 applet version/config read
- random byte generation
- Secure Object existence/type/size/list/delete helpers
- development EC key generation
- public-key readout from EC key objects
- P-256 ECDH shared-secret derivation

The practical firmware-envelope key-agreement path is:

```text
P-256 ECDH + HKDF-SHA256 + AES-256-GCM
```

X25519 key generation and public-key export may work on the tested SE050 applet 7.2.0 environment, but `ECDHGenerateSharedSecret` consistently returned `SW=0x6985` during the investigation. Because P-256 works through the same ECDH APDU family, the CLI treats X25519 derive as unsupported and keeps P-256 as the mainline path.

## CLI

The installed command is:

```sh
se050ctl
```

Common options:

```sh
-b, --bus <n>          I2C bus number, e.g. 0 for /dev/i2c-0
-a, --address <hex>    SE050 I2C address, default: 0x48
-d, --debug            Print T=1 over I2C frames
```

### UID

```sh
se050ctl uid -b 0
se050ctl uid -b 0 --colon
```

### Version and feature bitmap

```sh
se050ctl version -b 0
```

### Random

```sh
se050ctl random -b 0 --len 32
se050ctl random -b 0 --len 32 --colon
```

### Secure Object inspection

Object references can be specified in one of these forms:

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

Examples:

```sh
se050ctl exists -b 0 --name uid
se050ctl info -b 0 --name uid
se050ctl list -b 0 --annotate
se050ctl list -b 0 --area dev --annotate
```

### Development P-256 key agreement

`se050ctl keygen` defaults to P-256.

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

sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

Expected shape:

- P-256 public keys are 65-byte uncompressed points: `0x04 || X(32) || Y(32)`
- ECDH shared secrets are 32 bytes
- A→B and B→A shared secrets must match

## Object ID policy used by `se050ctl`

`se050ctl` is a development and diagnostic tool, not a production provisioning tool. Creation and deletion are intentionally limited to the development range.

| Area | Range | `se050ctl` create/delete |
|---|---:|---|
| vendor | `0x10000000..0x10000FFF` | no |
| customer | `0x20000000..0x2000FFFF` | no |
| dev | `0x30000000..0x3000FFFF` | yes |
| nxp | `0x7FFF0000..0x7FFFFFFF` | no |
| internal | `0xF0000000..0xFFFFFFFF` | no |

Future production tooling should be split from this CLI, for example:

- `se050-provision`: production object creation and no-delete policy management
- `fwkeys` / `fw-envelope`: manifest/envelope processing
- `fw-update`: A/B firmware update application

## Library layout

```text
src/se050_nim.nim
src/se050_nim/apdu.nim
src/se050_nim/errors.nim
src/se050_nim/i2c.nim
src/se050_nim/keys.nim
src/se050_nim/management.nim
src/se050_nim/objects.nim
src/se050_nim/random.nim
src/se050_nim/tlv.nim
src/se050_nim/transport.nim
src/se050_nim/uid.nim
src/se050ctl.nim
```

The library layer provides low-level primitives. Product policy, firmware package parsing, envelope formats, signing policy, and A/B update logic should live above it.

## Build

```sh
nimble build
```

Dependencies are intentionally small:

```nim
requires "nim >= 2.2.10"
requires "results >= 0.5.1"
requires "argparse >= 4.0.2"
```

Keep the `results` dependency as `>= 0.5.1`; using `> 0.5.1` can prevent builds when `0.5.1` is the available version.

## License

MIT License
