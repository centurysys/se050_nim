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
| NXP factory Cloud ECC identity 0 | `0xF0000100` / `0xF0000101` | P-256 key pair + certificate / NXP | variant-dependent, read-only use |
| NXP factory Cloud ECC identity 1 | `0xF0000102` / `0xF0000103` | P-256 key pair + certificate / NXP | variant-dependent, read-only use |
| NXP factory Cloud RSA identity 0 | `0xF0000110` / `0xF0000111` | RSA-2048 key pair + certificate / NXP | variant-dependent, read-only use |
| NXP factory Cloud RSA identity 1 | `0xF0000112` / `0xF0000113` | RSA-2048 key pair + certificate / NXP | variant-dependent, read-only use |
| test firmware KEX | `0x30000100` | P-256 key pair / dev | exporter implemented and tested |
| production firmware KEX | `0x20000100` | P-256 key pair / customer | creation CLI and generic mutation guard implemented; irreversible device test pending |
| test TLS identity key0 A/B | `0x30000200..0x30000201` | P-256 key pair / dev | identity number + A/B slot, device-tested |
| test TLS identity key1 A/B | `0x30000202..0x30000203` | P-256 key pair / dev | multi-identity mapping device-tested |
| production TLS identities | `0x20000200..` | P-256 key pair / customer | identity number + A/B slot, creation through TLS-specific CLI only |

Firmware KEX uses the same lower index `0x0100` for test and production. TLS client identities use `0x0200` as the base and derive Object IDs as `identity * 2 + slotOffset`. Test and production keep matching lower 16-bit indices while the Object area separates their lifecycle.

## NXP factory cloud identity objects

The known cloud connection credentials in `0xF0000100..0xF0000113` are treated as NXP factory-provisioned objects. Their presence depends on the SE050 variant/configuration, so inspect the target with `se050ctl factory-list` before use.

`factory-cert`, `factory-pubkey`, and `factory-key-ref` are read-only. The generic `keygen` / `delete` mutation guard continues to reject the entire `0xF0000000..0xFFFFFFFF` internal range.

See [`factory-identities.md`](factory-identities.md).

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

TLS identity keys remain deletable in production because certificate/key rotation is an explicit requirement. WRITE and GEN stay disabled so an existing identity key cannot be silently overwritten or regenerated in place. Test and production use the same policy semantics, with the Object ID area, identity number, and A/B slot defining their lifecycle.

## TLS client identity profiles

TLS client identities are cloud-neutral X.509/mTLS signing keys. To support independent key pairs for multiple services, each `identity` number owns an A/B slot pair.

Object IDs are derived as:

```text
test:       0x30000200 + identity * 2 + slotOffset
production: 0x20000200 + identity * 2 + slotOffset
slotOffset: A=0, B=1
```

Examples:

| Profile | Identity | Slot | Object ID | Policy |
|---|---:|:---:|---:|---:|
| test | 0 | A | `0x30000200` | `0x10240000` |
| test | 0 | B | `0x30000201` | `0x10240000` |
| test | 1 | A | `0x30000202` | `0x10240000` |
| test | 1 | B | `0x30000203` | `0x10240000` |
| production | 0 | A | `0x20000200` | `0x10240000` |
| production | 0 | B | `0x20000201` | `0x10240000` |
| production | 1 | A | `0x20000202` | `0x10240000` |
| production | 1 | B | `0x20000203` | `0x10240000` |

`identity 0` preserves the original A/B Object IDs. `identity 1` and later identities can be assigned to separate services or endpoints without sharing a private key.

The policy is `SIGN + READ + DELETE` for every identity and slot. The private key is generated inside the SE050; READ is used for the public key. Each identity can rotate independently through its A/B pair: prepare a new key and certificate in the inactive slot, verify connectivity, switch the active slot, then delete and reuse the old slot.

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
