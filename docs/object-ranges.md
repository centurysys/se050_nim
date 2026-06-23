# SE050 Object Ranges and Tool Policy

This document records the object ID namespace policy used by `se050ctl` and the intended split between the diagnostic CLI and future production provisioning tools.

## Object ID ranges

`se050ctl` classifies Secure Object IDs into the following ranges:

| Area | Range | `se050ctl` creation | `se050ctl` deletion | Intended owner |
| --- | --- | ---: | ---: | --- |
| `vendor` | `0x10000000..0x10000FFF` | no | no | future vendor/provisioning tool |
| `customer` | `0x20000000..0x2000FFFF` | no | no | future product provisioning tool |
| `dev` | `0x30000000..0x3000FFFF` | yes | yes | development and diagnostics |
| `nxp` | `0x7FFF0000..0x7FFFFFFF` | no | no | NXP/pre-provisioned objects |
| `internal` | `0xF0000000..0xFFFFFFFF` | no | no | internal/platform objects |

Known object:

| Name | Object ID | Notes |
| --- | ---: | --- |
| `uid` | `0x7FFF0206` | SE050 unique ID object |

## Why `se050ctl` only writes `dev`

`se050ctl` is a development and diagnostic CLI. It is allowed to create and delete only development objects. This keeps experiments safe and prevents accidental destruction of production keys.

Production provisioning needs different behavior:

- write outside the development range
- apply final production policy
- allow one-time provisioning semantics
- disallow deletion where appropriate
- emit factory registration records
- handle re-run and partial-failure recovery

Those responsibilities belong in a separate tool such as `se050-provision` or `se050-kitting`.

## Object reference syntax

`se050ctl` accepts exactly one object reference form:

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

`--area` and `--index` are resolved by adding the area base to the relative index.

Examples:

| Reference | Object ID |
| --- | ---: |
| `--area dev --index 0x100` | `0x30000100` |
| `--area customer --index 0x100` | `0x20000100` |
| `--name uid` | `0x7FFF0206` |

## Development key policy

Development EC key pairs created by `se050ctl keygen` use a deliberately permissive development policy.

The current policy allows:

- key agreement
- public key read
- write/generate during development iteration
- delete

This policy is useful for diagnostics, but it is not a production policy.

## Library freedom and CLI safety

`se050_nim` is a library, not a safety wrapper for every product workflow. Its raw primitives accept caller-provided object IDs, including `customer` and `vendor` ranges, because higher-level kitting/provisioning tools must be able to write production objects intentionally.

`se050ctl` is different. It is a diagnostic CLI that may be shipped with products, so its write/delete commands remain restricted to the development range. Do not add production policy shortcuts to `se050ctl` simply because the library can perform the raw operation.

## Production policy belongs in provisioning tools

A future provisioning tool should make production policy explicit and reviewable. Examples:

- P-256 device key in `customer` area
- allow key agreement
- allow public-key export during provisioning if needed
- disallow delete after provisioning
- avoid write/overwrite after finalization
- optionally use authenticated sessions or platform policy when available

The library provides `EcKeyPolicy` builders for this purpose:

- `developmentEcKeyPolicy()` for scratch/dev keys
- `deviceEcKeyPolicy()` for provisioned device keys
- `oneTimeDeviceKeyPolicy()` to express final one-time device-key creation intent
- `customEcKeyPolicy(header)` for advanced callers that need raw policy headers

The provisioning tool, not `se050ctl`, should decide which object range and policy are valid for each production operation.

## Suggested future production layout

One possible production layout:

| Purpose | Area | Example ID | Notes |
| --- | --- | ---: | --- |
| device P-256 ECDH private key | `customer` | `0x20000100` | used to open firmware envelope keys |
| device metadata/version object | `customer` | `0x20000010` | optional; only if needed by product flow |
| factory/vendor reserved objects | `vendor` | `0x10000000..` | reserved for controlled provisioning |
| diagnostic scratch objects | `dev` | `0x30000000..` | safe to delete/recreate |

The exact production map should be fixed before kitting begins and versioned in the provisioning project.
