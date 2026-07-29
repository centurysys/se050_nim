import std/strutils
import std/unittest

import se050_nim

proc sampleRecord(
    serialNumber: string,
    uidByte: uint8 = 0x11'u8,
    keyByte: uint8 = 0x22'u8
): KittingRecord =
  result = KittingRecord(
    serialNumber: serialNumber,
    formatVersion: KittingCsvFormatVersion,
    profileKind: kpTest,
    createdAt: "2026-07-29T10:00:00Z",
    keyRole: KittingKeyRoleFirmwareKex,
    se050Uid: newSeq[uint8](Se050UidLength),
    keyObjectId: KittingTestFirmwareKexObjectId,
    nonce: newSeq[uint8](KittingNonceLength),
    publicKey: newSeq[uint8](65),
    attestationCertificate: @[0x30'u8, 0x00'u8],
    attestationContainer: @[0x01'u8]
  )

  for i in 0 ..< result.se050Uid.len:
    result.se050Uid[i] = uidByte

  result.publicKey[0] = 0x04'u8
  for i in 1 ..< result.publicKey.len:
    result.publicKey[i] = keyByte

suite "kitting CSV export merge":
  test "adds the first record":
    let incoming = sampleRecord("11900000014")
    let merged = mergeKittingRecord(newSeq[KittingRecord](), incoming)

    require merged.ok
    check merged.value.disposition == kcmdAdded
    check merged.value.recordCount == 1
    check merged.value.records == @[incoming]

  test "keeps an existing identical device key":
    let existing = sampleRecord("11900000014")
    var incoming = existing
    incoming.createdAt = "2026-07-29T10:01:00Z"
    incoming.nonce[0] = 0xAA'u8
    incoming.attestationContainer = @[0x02'u8]

    let merged = mergeKittingRecord(@[existing], incoming)

    require merged.ok
    check merged.value.disposition == kcmdUnchanged
    check merged.value.recordCount == 1
    check merged.value.records == @[existing]

  test "rejects a different public key in the same logical slot":
    let existing = sampleRecord("11900000014")
    let incoming = sampleRecord("11900000014", keyByte = 0x33'u8)

    let merged = mergeKittingRecord(@[existing], incoming)

    check not merged.ok
    check merged.error.kind == seKittingValidationFailed
    check merged.error.message.contains("different key")

  test "appends another device":
    let first = sampleRecord("11900000014")
    let second = sampleRecord("11900000015", uidByte = 0x44'u8, keyByte = 0x55'u8)

    let merged = mergeKittingRecord(@[first], second)

    require merged.ok
    check merged.value.disposition == kcmdAdded
    check merged.value.recordCount == 2
    check merged.value.records == @[first, second]
