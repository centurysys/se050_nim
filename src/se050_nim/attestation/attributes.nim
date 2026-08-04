# =============================================================================
# SE050 attested Secure Object attribute parsing
# =============================================================================
#
# Applet 7.2 ReadObject-with-Attestation returns the Secure Object attributes
# as a signed TAG_3 value. This module decodes the object identity, type,
# access-rule entries, origin, and object version without discarding the raw
# bytes covered by the attestation signature.

import std/strformat
import std/strutils

import ../errors

# =============================================================================
# Constants
# =============================================================================

const
  Se050AttestedAttributePolicyOffset* = 14
  Se050AttestedObjectVersionLength* = 4

  Se050SetIndicatorNotSet* = 0x01'u8
  Se050SetIndicatorSet* = 0x02'u8

  Se050ObjectOriginExternal* = 0x01'u8
  Se050ObjectOriginInternal* = 0x02'u8
  Se050ObjectOriginProvisioned* = 0x03'u8

  Se050AttestedObjectInfoLength* = 2

  MinimumPolicyEntryLength = 8
  MaximumPolicyEntryLength = 40

# =============================================================================
# Types
# =============================================================================

type
  AttestedObjectPolicy* = object
    ## One access-rule entry from the signed Secure Object attributes.
    encodedLength*: uint8
    authObjectId*: uint32
    header*: uint32
    extension*: seq[uint8]

  AttestedObjectAttributes* = object
    objectId*: uint32
    objectType*: uint8
    authAttribute*: uint8

    ## Bytes 6..13 have different names for authentication and ordinary
    ## objects. Keep both interpretations available to diagnostic callers.
    minimumAeadTagLength*: uint16
    authenticationAttempts*: uint16
    ownerAuthObjectId*: uint32
    rfu*: uint16
    maximumAuthenticationAttempts*: uint16

    policies*: seq[AttestedObjectPolicy]
    origin*: uint8
    objectVersionPresent*: bool
    objectVersion*: uint32
    raw*: seq[uint8]

# =============================================================================
# Internal helpers
# =============================================================================

proc readU16Be(data: openArray[uint8], index: int): uint16 =
  result =
    (uint16(data[index]) shl 8) or
    uint16(data[index + 1])

proc readU32Be(data: openArray[uint8], index: int): uint32 =
  result =
    (uint32(data[index]) shl 24) or
    (uint32(data[index + 1]) shl 16) or
    (uint32(data[index + 2]) shl 8) or
    uint32(data[index + 3])

# =============================================================================
# Public helpers
# =============================================================================

proc objectAuthenticationIndicatorName*(value: uint8): string =
  case value
  of Se050SetIndicatorNotSet:
    result = "not-set"
  of Se050SetIndicatorSet:
    result = "set"
  else:
    result = &"unknown-0x{value.toHex(2)}"

proc objectOriginName*(value: uint8): string =
  case value
  of Se050ObjectOriginExternal:
    result = "external"
  of Se050ObjectOriginInternal:
    result = "internal"
  of Se050ObjectOriginProvisioned:
    result = "provisioned"
  else:
    result = &"unknown-0x{value.toHex(2)}"

proc parseAttestedObjectSize*(objectInfo: openArray[uint8]): SE[uint16] =
  ## Parses TAG_4 from ReadObject-with-Attestation. For SE050/SE051 key objects,
  ## the field is the two-byte big-endian object size in bytes.
  if objectInfo.len != Se050AttestedObjectInfoLength:
    return fail[uint16](
      seInvalidResponse,
      &"attested object information must be {Se050AttestedObjectInfoLength} bytes; got {objectInfo.len}"
    )

  result = ok(readU16Be(objectInfo, 0))

proc parseAttestedObjectAttributes*(
    data: openArray[uint8]
): SE[AttestedObjectAttributes] =
  ## Parses the signed Secure Object attribute value returned by Applet 7.2.
  ##
  ## Layout used by the NXP Plug & Trust example:
  ##   object ID             4 bytes
  ##   object type           1 byte
  ##   auth indicator        1 byte
  ##   object metadata       8 bytes
  ##   zero or more policies variable
  ##   origin                1 byte
  ##   object version        optional 4 bytes
  if data.len < Se050AttestedAttributePolicyOffset + 1:
    return fail[AttestedObjectAttributes](
      seInvalidResponse,
      &"attested object attributes are too short: {data.len} bytes"
    )

  let authAttribute = data[5]
  if authAttribute != Se050SetIndicatorNotSet and
      authAttribute != Se050SetIndicatorSet:
    return fail[AttestedObjectAttributes](
      seInvalidResponse,
      &"attested object auth indicator is invalid: 0x{authAttribute.toHex(2)}"
    )

  var parsed = AttestedObjectAttributes(
    objectId: readU32Be(data, 0),
    objectType: data[4],
    authAttribute: authAttribute,
    ownerAuthObjectId: readU32Be(data, 8),
    raw: @data
  )

  if authAttribute == Se050SetIndicatorNotSet:
    parsed.minimumAeadTagLength = readU16Be(data, 6)
    parsed.rfu = readU16Be(data, 12)
  else:
    parsed.authenticationAttempts = readU16Be(data, 6)
    parsed.maximumAuthenticationAttempts = readU16Be(data, 12)

  var index = Se050AttestedAttributePolicyOffset

  # Access-rule length values are at least four, while valid origin values are
  # 1..3. This is the same delimiter used by the NXP middleware example.
  while index < data.len and data[index] >= 4'u8:
    let entryLength = int(data[index])
    if entryLength < MinimumPolicyEntryLength or
        entryLength > MaximumPolicyEntryLength:
      return fail[AttestedObjectAttributes](
        seInvalidResponse,
        &"attested policy entry length is invalid: {entryLength}"
      )

    let entryEnd = index + 1 + entryLength
    if entryEnd > data.len:
      return fail[AttestedObjectAttributes](
        seInvalidResponse,
        "attested policy entry is truncated"
      )

    var policy = AttestedObjectPolicy(
      encodedLength: data[index],
      authObjectId: readU32Be(data, index + 1),
      header: readU32Be(data, index + 5)
    )

    let extensionStart = index + 9
    if extensionStart < entryEnd:
      policy.extension = @data[extensionStart ..< entryEnd]
    else:
      policy.extension = @[]

    parsed.policies.add(policy)
    index = entryEnd

  if index >= data.len:
    return fail[AttestedObjectAttributes](
      seInvalidResponse,
      "attested object origin is missing"
    )

  parsed.origin = data[index]
  if parsed.origin != Se050ObjectOriginExternal and
      parsed.origin != Se050ObjectOriginInternal and
      parsed.origin != Se050ObjectOriginProvisioned:
    return fail[AttestedObjectAttributes](
      seInvalidResponse,
      &"attested object origin is invalid: 0x{parsed.origin.toHex(2)}"
    )
  inc index

  let remaining = data.len - index
  case remaining
  of 0:
    parsed.objectVersionPresent = false
  of Se050AttestedObjectVersionLength:
    parsed.objectVersionPresent = true
    parsed.objectVersion = readU32Be(data, index)
  else:
    return fail[AttestedObjectAttributes](
      seInvalidResponse,
      &"attested object attributes have {remaining} unexpected trailing bytes"
    )

  result = ok(parsed)
