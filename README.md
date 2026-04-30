# se050_nim

Lightweight Nim library for accessing NXP SE050 secure element over T=1 over I2C.

## Overview

`se050_nim` provides a minimal, dependency-free interface to communicate with SE050 devices.

It focuses on:
- Small footprint
- Simple API
- No dependency on NXP Plug & Trust middleware

## Features (current)

- T=1 over I2C transport
- ATR handling
- APDU exchange
- UID read (Object ID: `0x7FFF0206`)
- CLI example (`se050_uid`)

## Example

```
import se050_nim

let se = openSe050(0)

discard se.requestAtr()

let uid = se.readUidHex()
echo uid.get()
```

## CLI Tool

```
se050_uid -b 0
se050_uid -b 0 --colon
se050_uid -b 0 -d
```

## Design

```
transport (T=1 over I2C)
  ↓
APDU
  ↓
high-level modules (uid, future: object, crypto)
```

Low-level I2C is intentionally hidden.

## Future Work

Planned features:

- ReadObject / WriteObject
- Random number generation
- ECC key generation
- ECDSA signing / verification
- Public key retrieval
- Secure storage utilities

Long-term:

- Device authentication workflows
- Cloud integration helpers (Azure / AWS)
- Secure boot / firmware verification support

## Philosophy

- Keep it minimal
- Avoid heavy middleware
- Focus on embedded Linux use-cases
- Provide building blocks, not frameworks

## License

MIT License
