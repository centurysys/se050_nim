# SE050 Kitting Guide

This document describes how `se050-kitting-export` creates an Attestation-backed CSV and how `se050ctl kitting-verify` or the library APIs verify it.

## Current scope

Implemented:

- Applet 7.2.x ReadObject-with-Attestation
- NXP device certificate and attestation signature verification
- creation and reuse of test firmware KEX object `0x30000100`
- fixed-policy production firmware KEX creation path at `0x20000100`
- safe append and idempotent reuse of a multi-device CSV
- offline cryptographic verification of records
- local comparison with the current board and SE050

Not implemented:

- real-device no-delete/no-overwrite production tests
- a PC-only CSV verification executable
- firmware envelope generation, HKDF, AES-GCM, and decryption
- file locking and explicit `fsync()` for concurrent production writers

## Trust path

```text
NXP Attestation ECC Root
  └─ NXP Attestation ECC Intermediate
       └─ SE050 device certificate 0xF0000013
            └─ attestation key 0xF0000012
                 └─ signs firmware KEX public key and attributes
```

The Root and Intermediate certificates are stored at:

```text
src/se050_nim/certs/nxp-attestation-ecc-root.der
src/se050_nim/certs/nxp-attestation-ecc-intermediate.der
```

They are embedded with `staticRead()`. Kitting verification does not accept caller-supplied replacement trust anchors. Only the diagnostic `se050ctl attest-verify` command accepts explicit external DER files.

## Profiles

| Profile | Object ID | Curve/type | Policy | Lifecycle | CLI |
|---|---:|---|---:|---|---|
| `test` | `0x30000100` | P-256 / `0x29` | `0x04240000` | KA/READ/DELETE, no overwrite | implemented |
| `production` | `0x20000100` | P-256 / `0x29` | `0x04200000` | KA/READ, no delete or overwrite | CLI implemented; device test pending |

The test policy matches production KA/READ permissions and adds DELETE only. It does not allow overwriting or regenerating an existing key in place.

## Board serial

The board serial is always read from:

```text
/proc/device-tree/board/serialno
```

Only ASCII digits are accepted. Trailing NUL/CR/LF bytes are removed, while leading zeroes are preserved. There is no manual serial override.

The SE050 does not know the board serial. The exporter derives the 16-byte freshness from the serial, creation time, profile, and nonce, and asks the SE050 to sign that freshness. Modifying the serial in the CSV therefore breaks verification.

Offline verification cannot detect a serial that was already wrong in Device Tree during kitting, or a later physical transfer of the SE050 to another board.

## Generate a test CSV

```sh
se050-kitting-export test \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

The exporter:

1. validates the Device Tree serial;
2. requires Applet 7.2.x;
3. creates `0x30000100` with policy `0x04240000` when absent;
4. reads `0xF0000013`, the SE050 UID, and the public key;
5. verifies every existing CSV record;
6. accepts an existing matching record as `already valid`;
7. obtains a new nonce and ReadObject-with-Attestation response;
8. verifies the certificate chain, signature, attributes, and policy;
9. compares the live UID, type, persistence, and public key;
10. replaces the CSV through a same-directory temporary file and rename;
11. re-reads and verifies the written CSV.

First-run output includes:

```text
CSV record: added
self-verification: valid
```

A repeated run includes:

```text
CSV record: already valid
```

## Production CSV generation

The `production` command internally generates a P-256 key at fixed Object ID `0x20000100` with policy `0x04200000`, which allows KA/READ only. DELETE, WRITE, and GEN are not granted.

```sh
se050-kitting-export production \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

This operation is irreversible. Perform the first device test on a non-shipping evaluation unit.

Before creating an absent production key, the exporter completes these reversible checks:

1. board serial and Applet version;
2. device certificate read and chain validation against the embedded trust store;
3. SE050 UID read;
4. offline verification of every existing CSV record;
5. when a CSV record already exists for the same serial/profile, confirmation that the target object also exists.

The key is created only when the target object is absent. Existing objects are never deleted or overwritten; they are reused only after Attestation verifies type, origin, policy, and public key. Any mismatch stops the operation.

If CSV writing fails after key creation, a later run reuses the existing key and can regenerate the Attestation-backed record.

## Existing generic development key

Generic `se050ctl keygen` uses policy `0x043C0000`. A key created that way at `0x30000100` is rejected because kitting requires `0x04240000`.

After confirming that the object is a disposable test object, delete it explicitly:

```sh
se050ctl delete -b 0 --area dev --index 0x100
```

The exporter never auto-deletes a key whose policy does not match.

## CSV format

```text
serialno,format_version,profile,created_at,key_role,se050_uid,key_object_id,nonce,public_key,attestation_cert,attestation
```

| Field | Meaning |
|---|---|
| `serialno` | board serial from Device Tree |
| `format_version` | currently `1` |
| `profile` | `test` or `production` |
| `created_at` | UTC `YYYY-MM-DDTHH:MM:SSZ` |
| `key_role` | currently `firmware-kex` |
| `se050_uid` | SE050 UID |
| `key_object_id` | firmware KEX Object ID |
| `nonce` | 16-byte random nonce |
| `public_key` | 65-byte uncompressed P-256 key |
| `attestation_cert` | SE050 device certificate DER |
| `attestation` | versioned request/response/signature container |

Binary fields use strict Base64. The logical key is `serialno + profile + key_role`. A different UID, Object ID, or public key for the same logical key is a conflict and is never overwritten automatically.

## Offline verification

`verifyKittingRecord()` and `verifyKittingCsvRecord()` do not use I2C. A PC can verify:

- CSV structure, Base64, timestamp, and profile;
- reconstructed metadata-bound freshness;
- the device certificate chain to the NXP Root;
- the Applet 7.2 ECDSA attestation signature;
- signed object ID, type, origin, size, and policy;
- signed SE050 UID and public key;
- tampering with the serial or record fields.

A PC cannot prove that the same SE050 and key are still installed on that physical board. For a trusted factory flow, offline verification is still suitable before importing records into a database.

A dedicated PC-only CLI is not implemented yet; use the library API for now.

## Local-device verification

```sh
se050ctl kitting-verify \
  -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

In addition to offline checks, this compares:

- `/proc/device-tree/board/serialno`;
- live SE050 UID;
- P-256 key-pair object type;
- persistent indicator;
- live public key.

The CLI default profile is `production`. Use `--profile test` for test CSV records and either the default or `--profile production` for production records.

## Padded device certificate BinaryFiles

Some devices provision `0xF0000013` as a BinaryFile larger than the actual DER certificate, with a zero-filled tail.

The implementation reads the complete size reported by ReadSize, extracts the leading DER SEQUENCE using its self-described length, and accepts the tail only when every trailing byte is `0x00`.

## CSV durability

The current exporter writes the complete CSV to a temporary file in the same directory and then renames it over the destination. This prevents readers from seeing a partial CSV.

Additional CSV-writer hardening still needs:

- locking against concurrent writers;
- explicit `fsync()` of the temporary file and directory;

## Next layer

The device-specific P-256 public key recorded in the CSV will later feed the firmware-envelope generator:

```text
Kitting CSV / database
  -> device public key
  -> server ephemeral P-256 ECDH
  -> HKDF-SHA256
  -> AES-256-GCM wrapping of the release CEK
  -> shared encrypted firmware + per-device envelope
```
