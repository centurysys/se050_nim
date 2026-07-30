# SE050 Object Ranges and Tool Policy

This document defines the Object IDs, access policies, and responsibility boundaries used by `se050ctl` and the kitting exporter.

## Object ID ranges

| Area | Range | `se050ctl` create/delete | Intended use |
|---|---|---:|---|
| `vendor` | `0x10000000..0x10000FFF` | no | controlled vendor provisioning |
| `customer` | `0x20000000..0x2000FFFF` | no | production product objects |
| `dev` | `0x30000000..0x3000FFFF` | yes | development, diagnostics, deletable tests |
| `nxp` | `0x7FFF0000..0x7FFFFFFF` | no | NXP/pre-provisioned objects |
| `internal` | `0xF0000000..0xFFFFFFFF` | no | NXP internal/platform objects |

`se050ctl keygen` and `delete` are limited to the development range. Raw library APIs do not enforce that limit because higher-level provisioning tools must be able to address customer/vendor ranges intentionally.

## Objects currently used

| Name / purpose | Object ID | Type/owner | Status |
|---|---:|---|---|
| `uid` | `0x7FFF0206` | NXP unique ID | read path verified |
| NXP attestation key | `0xF0000012` | P-256 key pair / NXP | pre-provisioned, used for signatures |
| NXP device certificate | `0xF0000013` | BinaryFile / NXP | pre-provisioned, used for X.509 validation |
| test firmware KEX | `0x30000100` | P-256 key pair / dev | exporter implemented and tested |
| production firmware KEX | `0x20000100` | P-256 key pair / customer | profile/API defined; creation CLI not implemented |

Test and production use the same lower index `0x0100`, while the high byte makes the profile visible.

## Object references

```sh
--id 0x30000100
--area dev --index 0x100
--name uid
```

| Reference | Object ID |
|---|---:|
| `--area dev --index 0x100` | `0x30000100` |
| `--area customer --index 0x100` | `0x20000100` |
| `--name uid` | `0x7FFF0206` |

## EC key policies

| API / purpose | Header | KA | READ | WRITE | GEN | DELETE |
|---|---:|:---:|:---:|:---:|:---:|:---:|
| `developmentEcKeyPolicy()` | `0x043C0000` | yes | yes | yes | yes | yes |
| `testDeviceKeyPolicy()` | `0x04240000` | yes | yes | no | no | yes |
| `deviceEcKeyPolicy()` | `0x04200000` | yes | yes | no | no | no |
| `oneTimeDeviceKeyPolicy()` | `0x04200000` | yes | yes | no | no | no |

`oneTimeDeviceKeyPolicy()` currently has the same effective header as `deviceEcKeyPolicy()`. The distinct API name records irreversible provisioning intent and leaves room for future Applet-specific attributes.

## Test kitting safety

`se050-kitting-export test` targets only `0x30000100` and fixes the policy at `0x04240000`.

An existing object is never overwritten. The exporter verifies its ID, type, origin, size, policy, and public key through Attestation. A correct test key is reused. A generic development-policy key (`0x043C0000`) is rejected and never deleted automatically.

## Production kitting

The production profile is defined as:

```text
Object ID: 0x20000100
Curve: P-256
Policy: 0x04200000
```

The current exporter implements only the `test` subcommand. Before production creation is added, a non-shipping evaluation device should verify:

- successful first creation;
- matching attested policy, origin, and type;
- reuse after a power cycle;
- rejection of overwrite, regenerate, and delete;
- recovery by re-running after a CSV write failure.

No irreversible create/delete shortcut belongs in the diagnostic CLI.

## NXP reserved object protection

NXP objects in `0x7FFF...` and `0xF000...` are outside `se050ctl` write/delete commands. Attestation key `0xF0000012` and certificate `0xF0000013` are read and verified only.

## Future layout

| Purpose | Area | Example Object ID |
|---|---|---:|
| production firmware KEX private key | `customer` | `0x20000100` |
| product metadata/version | `customer` | `0x20000010` |
| vendor-managed objects | `vendor` | `0x10000000..` |
| disposable diagnostic objects | `dev` | `0x30000000..` |

Freeze and version the production map before irreversible factory kitting begins.
