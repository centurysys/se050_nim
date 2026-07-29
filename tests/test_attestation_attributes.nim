import std/unittest

import se050_nim

proc appendU16Be(data: var seq[uint8], value: uint16) =
  data.add(uint8((value shr 8) and 0xFF))
  data.add(uint8(value and 0xFF))

proc appendU32Be(data: var seq[uint8], value: uint32) =
  data.add(uint8((value shr 24) and 0xFF))
  data.add(uint8((value shr 16) and 0xFF))
  data.add(uint8((value shr 8) and 0xFF))
  data.add(uint8(value and 0xFF))

proc encodedAttributes(
    profile: KittingProfile,
    origin: uint8 = Se050ObjectOriginInternal,
    policyHeaderOverride: uint32 = 0'u32,
    includeVersion: bool = true
): seq[uint8] =
  result.appendU32Be(profile.keyObjectId)
  result.add(profile.expectedKeyType())
  result.add(Se050SetIndicatorNotSet)

  # Non-authentication object metadata.
  result.appendU16Be(0'u16)
  result.appendU32Be(0'u32)
  result.appendU16Be(0'u16)

  result.add(0x08'u8)
  result.appendU32Be(0'u32)
  let header =
    if policyHeaderOverride != 0'u32:
      policyHeaderOverride
    else:
      policyHeader(profile.keyPolicy())
  result.appendU32Be(header)

  result.add(origin)
  if includeVersion:
    result.appendU32Be(1'u32)

suite "SE050 attested object attributes":
  test "parses Applet 7.2 key attributes without losing policy data":
    let profile = testKittingProfile()
    let raw = encodedAttributes(profile)
    let parsed = parseAttestedObjectAttributes(raw)

    check parsed.ok
    check parsed.value.raw == raw
    check parsed.value.objectId == profile.keyObjectId
    check parsed.value.objectType == Se050TypeEcKeyPairNistP256
    check parsed.value.authAttribute == Se050SetIndicatorNotSet
    check parsed.value.ownerAuthObjectId == 0'u32
    check parsed.value.policies.len == 1
    check parsed.value.policies[0].encodedLength == 8'u8
    check parsed.value.policies[0].authObjectId == 0'u32
    check parsed.value.policies[0].header == policyHeader(profile.keyPolicy())
    check parsed.value.policies[0].extension.len == 0
    check parsed.value.origin == Se050ObjectOriginInternal
    check parsed.value.objectVersionPresent
    check parsed.value.objectVersion == 1'u32

  test "accepts legacy attributes without an object version":
    let parsed = parseAttestedObjectAttributes(
      encodedAttributes(testKittingProfile(), includeVersion = false)
    )

    check parsed.ok
    check not parsed.value.objectVersionPresent

  test "rejects a truncated policy entry":
    var raw = encodedAttributes(testKittingProfile())
    raw.setLen(18)

    let parsed = parseAttestedObjectAttributes(raw)
    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects an invalid authentication indicator":
    var raw = encodedAttributes(testKittingProfile())
    raw[5] = 0'u8

    let parsed = parseAttestedObjectAttributes(raw)
    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "rejects an invalid object origin":
    var raw = encodedAttributes(testKittingProfile())
    raw[^5] = 0'u8

    let parsed = parseAttestedObjectAttributes(raw)
    check not parsed.ok
    check parsed.error.kind == seInvalidResponse

  test "parses the two-byte object size":
    let size = parseAttestedObjectSize(@[0x00'u8, 0x20'u8])
    check size.ok
    check size.value == 32'u16

    let invalid = parseAttestedObjectSize(@[
      0x00'u8, 0x00'u8, 0x00'u8, 0x20'u8
    ])
    check not invalid.ok
