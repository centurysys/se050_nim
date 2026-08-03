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
| production firmware KEX | `0x20000100` | P-256 key pair / customer | creation CLI and generic mutation guard implemented; irreversible device test pending |
| test TLS identity slot A | `0x30000200` | P-256 key pair / dev | profile and policy defined |
| test TLS identity slot B | `0x30000201` | P-256 key pair / dev | profile and policy defined |
| production TLS identity slot A | `0x20000200` | P-256 key pair / customer | profile and policy defined |
| production TLS identity slot B | `0x20000201` | P-256 key pair / customer | profile and policy defined |

Firmware KEX uses the same lower index `0x0100` for test and production. TLS client identity uses `0x0200`/`0x0201` for slots A/B, while the high byte distinguishes test from production.

## Production firmware KEX ID reservation guard

`0x20000100` is explicitly reserved at the application layer for the production firmware KEX key.

Before its general range checks, `se050ctl` calls a shared guard that rejects generic mutation operations against this ID:

- create;
- key generation;
- write / overwrite;
- delete.

The currently implemented mutating `se050ctl` commands, `keygen` and `delete`, use this guard. Future write/import commands must use the same guard.

Read and verification operations such as `info`, `exists`, `pubkey`, and Attestation remain allowed. The production exporter uses a dedicated raw-library path after fixing and validating the Object ID and policy.

This guard prevents accidents; it is not the security boundary. It does not block custom APDUs or other middleware. The final delete and overwrite protection comes from the one-time policy stored with the Secure Object inside the SE050.

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

| API / purpose | Header | SIGN | KA | READ | WRITE | GEN | DELETE |
|---|---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `developmentEcKeyPolicy()` | `0x043C0000` | no | yes | yes | yes | yes | yes |
| `developmentSigningEcKeyPolicy()` | `0x103C0000` | yes | no | yes | yes | yes | yes |
| TLS identity `keyPolicy()` | `0x10240000` | yes | no | yes | no | no | yes |
| `testDeviceKeyPolicy()` | `0x04240000` | no | yes | yes | no | no | yes |
| `deviceEcKeyPolicy()` | `0x04200000` | no | yes | yes | no | no | no |
| `oneTimeDeviceKeyPolicy()` | `0x04200000` | no | yes | yes | no | no | no |

`oneTimeDeviceKeyPolicy()` currently has the same effective header as `deviceEcKeyPolicy()`. The distinct API name records irreversible provisioning intent and leaves room for future Applet-specific attributes.

TLS identity keys remain deletable in production because certificate/key rotation is an explicit requirement. WRITE and GEN stay disabled so an existing identity key cannot be silently overwritten or regenerated in place. Test and production use the same policy semantics, with the Object ID area and A/B slot defining their lifecycle.

## TLS client identity A/B profiles

TLS client identity profiles are cloud-neutral X.509/mTLS signing-key profiles with four fixed objects:

| Profile | Slot | Object ID | Policy |
|---|:---:|---:|---:|
| test | A | `0x30000200` | `0x10240000` |
| test | B | `0x30000201` | `0x10240000` |
| production | A | `0x20000200` | `0x10240000` |
| production | B | `0x20000201` | `0x10240000` |

The policy is `SIGN + READ + DELETE`. The private key is generated inside the SE050; READ is used for the public key. A/B rotation prepares a new key and certificate in the inactive slot, verifies connectivity, switches the active identity, and then allows the old slot to be deleted and reused.

AWS IoT Core / Azure IoT Hub endpoints, device/Thing IDs, CSR enrollment, certificate registration, and MQTT parameters remain outside this profile.

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

```sh
se050-kitting-export production \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

`se050-kitting-export production` uses only this fixed ID and fixed policy and never deletes or overwrites an existing object. The first irreversible device test should use a non-shipping evaluation unit and verify:

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
| production TLS identity slot A/B | `customer` | `0x20000200..0x20000201` |
| test TLS identity slot A/B | `dev` | `0x30000200..0x30000201` |
| product metadata/version | `customer` | `0x20000010` |
| vendor-managed objects | `vendor` | `0x10000000..` |
| disposable diagnostic objects | `dev` | `0x30000000..` |

Freeze and version the production map before irreversible factory kitting begins.
