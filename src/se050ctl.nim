# =============================================================================
# se050ctl
# =============================================================================
#
# Development/diagnostic CLI for se050_nim.
#
# This tool intentionally stays at the low-level SE050 primitive layer.
# Firmware package, manifest, and envelope handling should live in higher layers
# such as fwkeys / fw-envelope / fw-update.

import std/options
import std/strformat
import std/strutils

import argparse
import se050_nim

# =============================================================================
# SE050 object namespace policy used by this CLI
# =============================================================================

const
  VendorReservedStart = 0x10000000'u32
  VendorReservedEnd = 0x10000FFF'u32

  CustomerStart = 0x20000000'u32
  CustomerEnd = 0x2000FFFF'u32

  # se050ctl intentionally keeps key creation in this shallow-water development
  # range. Vendor-reserved IDs are left to a dedicated provisioning tool, not
  # this user-facing diagnostic CLI.
  DevelopmentStart = 0x30000000'u32
  DevelopmentEnd = 0x3000FFFF'u32

  # NXP-reserved applet objects such as 0x7FFF0206 unique ID live here.
  NxpReservedStart = 0x7FFF0000'u32
  NxpReservedEnd = 0x7FFFFFFF'u32

  # Objects observed in this range are treated as internal/platform objects.
  InternalReservedStart = 0xF0000000'u32
  InternalReservedEnd = 0xFFFFFFFF'u32

  # Known NXP/pre-provisioned object IDs whose role is already confirmed by the
  # current low-level implementation.
  KnownUidObjectId = 0x7FFF0206'u32

# =============================================================================
# Types
# =============================================================================

type
  ObjectArea = enum
    oaVendor,
    oaCustomer,
    oaDev,
    oaNxp,
    oaInternal,
    oaOther

  ObjectAreaSpec = object
    area: ObjectArea
    name: string
    first: uint32
    last: uint32
    creatableBySe050ctl: bool
    deletableBySe050ctl: bool

  ObjectRef = object
    objectId: uint32
    source: string

# =============================================================================
# Utility
# =============================================================================

proc parseBusNumber(s: string): int =
  let v = parseInt(s.strip())
  if v < 0:
    raise newException(ValueError, &"I2C bus number must be >= 0: {s}")
  result = v

proc parseI2cAddress(s: string): uint8 =
  ## Parses a 7-bit I2C address.
  ##
  ## The value is treated as hexadecimal to preserve the existing se050_uid
  ## behavior. Both "48" and "0x48" mean 0x48.
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  let v = parseHexInt(t)
  if v < 0 or v > 0x7F:
    raise newException(ValueError, &"I2C address must be in 7-bit range: {s}")

  result = uint8(v)

proc parseLength(s: string, minValue: int, maxValue: int): int =
  let v = parseInt(s.strip())
  if v < minValue or v > maxValue:
    raise newException(ValueError, &"length must be in range {minValue}..{maxValue}: {s}")
  result = v

proc parseObjectId(s: string): uint32 =
  ## Parses an SE050 Secure Object identifier.
  ##
  ## The value is treated as hexadecimal. Both "10000100" and "0x10000100"
  ## mean 0x10000100.
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  if t.len == 0:
    raise newException(ValueError, "object id is empty")

  let v = parseHexInt(t)
  if v < 0:
    raise newException(ValueError, &"object id must be >= 0: {s}")

  result = uint32(v)

proc parseIndex(s: string): uint32 =
  ## Parses an area-relative object index.
  ##
  ## Decimal is accepted by default, and 0x-prefixed values are accepted as
  ## hexadecimal. This keeps `--index 0, 1, 2...` convenient while still allowing
  ## values such as `--index 0x100` during low-level work.
  let trimmed = s.strip()
  if trimmed.len == 0:
    raise newException(ValueError, "object index is empty")

  let v =
    if trimmed.startsWith("0x") or trimmed.startsWith("0X"):
      parseHexInt(trimmed[2 .. ^1])
    else:
      parseInt(trimmed)

  if v < 0:
    raise newException(ValueError, &"object index must be >= 0: {s}")

  result = uint32(v)

proc parseHexByte(s: string): uint8 =
  ## Parses a hexadecimal byte value.
  var t = s.strip()
  if t.startsWith("0x") or t.startsWith("0X"):
    t = t[2 .. ^1]

  if t.len == 0:
    raise newException(ValueError, "hex byte is empty")

  let v = parseHexInt(t)
  if v < 0 or v > 0xFF:
    raise newException(ValueError, &"hex byte must be in range 0x00..0xFF: {s}")

  result = uint8(v)

proc printSe050Error(prefix: string, e: Se050Error) =
  stderr.writeLine &"{prefix}: {e.kind}: {e.message}"
  if e.sw != 0:
    stderr.writeLine &"SW=0x{e.sw.toHex(4)}"

proc objectIdHex(objectId: uint32): string =
  result = &"0x{objectId.toHex(8)}"

proc isInRange(value: uint32, first: uint32, last: uint32): bool =
  result = value >= first and value <= last

proc areaSpecs(): array[5, ObjectAreaSpec] =
  result = [
    ObjectAreaSpec(
      area: oaVendor,
      name: "vendor",
      first: VendorReservedStart,
      last: VendorReservedEnd,
      creatableBySe050ctl: false,
      deletableBySe050ctl: false
    ),
    ObjectAreaSpec(
      area: oaCustomer,
      name: "customer",
      first: CustomerStart,
      last: CustomerEnd,
      creatableBySe050ctl: false,
      deletableBySe050ctl: false
    ),
    ObjectAreaSpec(
      area: oaDev,
      name: "dev",
      first: DevelopmentStart,
      last: DevelopmentEnd,
      creatableBySe050ctl: true,
      deletableBySe050ctl: true
    ),
    ObjectAreaSpec(
      area: oaNxp,
      name: "nxp",
      first: NxpReservedStart,
      last: NxpReservedEnd,
      creatableBySe050ctl: false,
      deletableBySe050ctl: false
    ),
    ObjectAreaSpec(
      area: oaInternal,
      name: "internal",
      first: InternalReservedStart,
      last: InternalReservedEnd,
      creatableBySe050ctl: false,
      deletableBySe050ctl: false
    )
  ]

proc areaName(area: ObjectArea): string =
  case area
  of oaVendor: "vendor"
  of oaCustomer: "customer"
  of oaDev: "dev"
  of oaNxp: "nxp"
  of oaInternal: "internal"
  of oaOther: "other"

proc findAreaSpec(name: string): Option[ObjectAreaSpec] =
  let normalized = name.strip().toLowerAscii()
  for spec in areaSpecs():
    if spec.name == normalized:
      return some(spec)
  result = none(ObjectAreaSpec)

proc classifyArea(objectId: uint32): ObjectArea =
  for spec in areaSpecs():
    if objectId.isInRange(spec.first, spec.last):
      return spec.area
  result = oaOther

proc areaLabel(objectId: uint32): string =
  result = objectId.classifyArea().areaName()

proc isVendorReservedObjectId(objectId: uint32): bool =
  result = objectId.classifyArea() == oaVendor

proc isProtectedReservedObjectId(objectId: uint32): bool =
  let area = objectId.classifyArea()
  result = area == oaNxp or area == oaInternal

proc isDevelopmentObjectId(objectId: uint32): bool =
  result = objectId.classifyArea() == oaDev

proc knownObjectName(objectId: uint32): string =
  case objectId
  of KnownUidObjectId:
    result = "uid"
  else:
    result = "-"

proc objectIdForKnownName(name: string): uint32 =
  case name.strip().toLowerAscii()
  of "uid", "unique-id", "unique_id":
    result = KnownUidObjectId
  else:
    raise newException(ValueError, &"unknown object name: {name}")

proc sourceCount(idText: string, areaText: string, indexText: string, nameText: string): int =
  if idText.strip().len > 0:
    inc result
  if nameText.strip().len > 0:
    inc result
  if areaText.strip().len > 0 or indexText.strip().len > 0:
    inc result

proc resolveObjectRef(
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string
): ObjectRef =
  ## Resolves one object reference from exactly one of:
  ##   --id 0x30000100
  ##   --area dev --index 0x100
  ##   --name uid
  let count = sourceCount(idText, areaText, indexText, nameText)
  if count == 0:
    raise newException(
      ValueError,
      "object reference is required: use --id, --area/--index, or --name"
    )
  if count > 1:
    raise newException(
      ValueError,
      "--id, --area/--index, and --name are mutually exclusive"
    )

  if idText.strip().len > 0:
    result.objectId = parseObjectId(idText)
    result.source = "id"
    return

  if nameText.strip().len > 0:
    result.objectId = objectIdForKnownName(nameText)
    result.source = &"name:{nameText.strip().toLowerAscii()}"
    return

  if areaText.strip().len == 0 or indexText.strip().len == 0:
    raise newException(ValueError, "--area and --index must be specified together")

  let spec = findAreaSpec(areaText)
  if spec.isNone:
    raise newException(
      ValueError,
      &"unknown area: {areaText}. Supported areas: vendor, customer, dev, nxp, internal"
    )

  let index = parseIndex(indexText)
  let maxIndex = spec.get().last - spec.get().first
  if index > maxIndex:
    raise newException(
      ValueError,
      &"index out of range for area {spec.get().name}: 0..0x{maxIndex.toHex(8)}"
    )

  result.objectId = spec.get().first + index
  result.source = &"area:{spec.get().name}[0x{index.toHex(8)}]"

proc deleteTargetError(objectId: uint32): Option[string] =
  if objectId == 0'u32:
    return some("object id 0x00000000 is not a valid delete target")

  if not objectId.isDevelopmentObjectId():
    return some(
      &"delete refused: {objectIdHex(objectId)} is outside the se050ctl development range " &
      &"0x{DevelopmentStart.toHex(8)}..0x{DevelopmentEnd.toHex(8)}"
    )

  result = none(string)

proc keygenTargetError(objectId: uint32): Option[string] =
  if objectId == 0'u32:
    return some("object id 0x00000000 is not a valid key generation target")

  if objectId.isProtectedReservedObjectId():
    return some(
      &"keygen refused: {objectIdHex(objectId)} is in a protected SE050 reserved range"
    )

  if objectId.isVendorReservedObjectId():
    return some(
      &"keygen refused: {objectIdHex(objectId)} is in the vendor reserved range; use a dedicated provisioning tool for vendor-reserved objects"
    )

  if not objectId.isDevelopmentObjectId():
    return some(
      &"keygen refused: {objectIdHex(objectId)} is outside the se050ctl development range 0x{DevelopmentStart.toHex(8)}..0x{DevelopmentEnd.toHex(8)}"
    )

  result = none(string)

proc parseCurveKind(s: string): EcCurveKind =
  case s.strip().toLowerAscii()
  of "p256", "prime256v1", "nist-p256", "nist_p256", "secp256r1":
    result = ecCurveP256
  of "x25519", "mont-dh-25519", "mont25519", "ecc-mont-dh-25519":
    result = ecCurveX25519
  else:
    raise newException(ValueError, &"unsupported curve for se050ctl keygen: {s}")

proc isReadableEcPublicObjectType(objectType: uint8): bool =
  ## Returns true for EC key-pair/public-key object types whose public key can
  ## be read using ReadObject.
  case objectType
  of 0x01, 0x03, 0x29, 0x2B, 0x65, 0x67, 0x69, 0x6B, 0x71, 0x73:
    result = true
  else:
    result = false

proc isUnsupportedX25519DeriveObjectType(objectType: uint8): bool =
  ## X25519 keygen/pubkey can be useful for diagnostics, but on the tested
  ## SE050 applet 7.2.0 path ECDHGenerateSharedSecret consistently returned
  ## SW=0x6985. Keep this guard in the CLI so the firmware-envelope path stays
  ## on the verified P-256 implementation.
  result = objectType in {
    Se050TypeEcKeyPairMontDh25519,
    Se050TypeEcPrivKeyMontDh25519
  }

proc expectedPeerPublicKeyLength(objectType: uint8): int =
  ## Returns the raw public-key length accepted by the current CLI derive path.
  ##
  ## NIST P-256 public keys are uncompressed points: 0x04 || X || Y.
  case objectType
  of Se050TypeEcKeyPair, Se050TypeEcKeyPairNistP256:
    result = 65
  else:
    result = 0

proc isDeriveKeyPairObjectType(objectType: uint8): bool =
  result = expectedPeerPublicKeyLength(objectType) > 0

proc bytesToRawString(data: openArray[uint8]): string =
  ## Converts raw bytes to a Nim string without changing byte values.
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc rawStringToBytes(data: string): seq[uint8] =
  ## Converts a Nim string read from a file into raw bytes.
  result = newSeq[uint8](data.len)
  for i, ch in data:
    result[i] = uint8(ord(ch))

proc typeText(objectType: uint8): string =
  result = &"0x{objectType.toHex(2)} ({objectTypeName(objectType)})"

proc transientText(indicator: Option[uint8]): string =
  if indicator.isSome:
    let v = indicator.get()
    result = &"0x{v.toHex(2)} ({transientIndicatorName(v)})"
  else:
    result = "n/a"

proc printResolvedObjectRef(objectRef: ObjectRef) =
  if objectRef.source != "id":
    echo &"ref: {objectRef.source}"

# =============================================================================
# Commands
# =============================================================================

proc openAndRequestAtr(busText: string, addressText: string, debug: bool): Se050Transport =
  let bus = parseBusNumber(busText)
  let address = parseI2cAddress(addressText)

  result = openSe050(bus, address = address, debug = debug)

  let atr = result.requestAtr()
  if not atr.ok:
    printSe050Error("ATR failed", atr.error)
    quit(1)

proc runUid(busText: string, addressText: string, debug: bool, separator: string): int =
  let se = openAndRequestAtr(busText, addressText, debug)

  let uid = se.readUidHex(separator = separator, selectFirst = true)
  if not uid.ok:
    printSe050Error("UID read failed", uid.error)
    return 1

  echo uid.value
  result = 0

proc runRandom(
    busText: string,
    addressText: string,
    debug: bool,
    lengthText: string,
    separator: string
): int =
  let length = parseLength(lengthText, 1, Se050MaxRandomLength)
  let se = openAndRequestAtr(busText, addressText, debug)

  let randomHex = se.getRandomHex(
    length = length,
    separator = separator,
    selectFirst = true
  )
  if not randomHex.ok:
    printSe050Error("GetRandom failed", randomHex.error)
    return 1

  echo randomHex.value
  result = 0

proc runVersion(
    busText: string,
    addressText: string,
    debug: bool
): int =
  let se = openAndRequestAtr(busText, addressText, debug)

  let version = se.getVersionInfo(selectFirst = true)
  if not version.ok:
    printSe050Error("GetVersion failed", version.error)
    return 1

  let v = version.value
  echo &"applet version: {v.major}.{v.minor}.{v.patch}"
  echo &"applet config: 0x{v.appletConfig.toHex(4)}"
  echo &"secure box version: {v.secureBoxMajor}.{v.secureBoxMinor}"
  echo "features:"
  for bit in knownFeatureBits():
    let mark = if v.hasFeature(bit): "yes" else: "no"
    echo &"  {featureName(bit)}: {mark}"

  if not v.hasFeature(ConfigFipsModeDisabled):
    echo "notes:"
    echo "  CONFIG_FIPS_MODE_DISABLED is not set."
    echo "  SE050 may reject ECDHGenerateSharedSecret with SW=0x6985 on this applet configuration."

  result = 0

proc runExists(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string,
    quiet: bool
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not quiet:
    let statusText = if exists.value: "exists" else: "missing"
    echo &"{objectIdHex(objectRef.objectId)}: {statusText}"

  result = if exists.value: 0 else: 1

proc runInfo(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  echo &"id: {objectIdHex(objectRef.objectId)}"
  printResolvedObjectRef(objectRef)
  echo &"area: {areaLabel(objectRef.objectId)}"
  let knownName = knownObjectName(objectRef.objectId)
  if knownName != "-":
    echo &"name: {knownName}"

  let existsText = if exists.value: "yes" else: "no"
  echo &"exists: {existsText}"

  if not exists.value:
    return 1

  let typ = se.readObjectType(objectId = objectRef.objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType failed", typ.error)
    return 1

  echo &"type: {typeText(typ.value.objectType)}"
  echo &"transient: {transientText(typ.value.transientIndicator)}"

  let size = se.readObjectSize(objectId = objectRef.objectId, selectFirst = false)
  if size.ok:
    echo &"size: {size.value}"
  else:
    echo "size: unavailable"
    stderr.writeLine &"ReadSize failed: {size.error.kind}: {size.error.message}"
    if size.error.sw != 0:
      stderr.writeLine &"SW=0x{size.error.sw.toHex(4)}"

  result = 0

proc runList(
    busText: string,
    addressText: string,
    debug: bool,
    filterText: string,
    areaText: string,
    annotate: bool
): int =
  let filter = parseHexByte(filterText)
  let areaFilter =
    if areaText.strip().len > 0:
      let spec = findAreaSpec(areaText)
      if spec.isNone:
        raise newException(
          ValueError,
          &"unknown area: {areaText}. Supported areas: vendor, customer, dev, nxp, internal"
        )
      some(spec.get().area)
    else:
      none(ObjectArea)

  let se = openAndRequestAtr(busText, addressText, debug)

  let ids = se.listObjectIds(filter = filter, selectFirst = true)
  if not ids.ok:
    printSe050Error("ReadIDList failed", ids.error)
    return 1

  for objectId in ids.value:
    let area = objectId.classifyArea()
    if areaFilter.isSome and area != areaFilter.get():
      continue

    if annotate:
      echo &"{objectIdHex(objectId)}  {area.areaName()}  {knownObjectName(objectId)}"
    else:
      echo objectIdHex(objectId)

  result = 0

proc runKeygen(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string,
    curveText: string
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  let curve = parseCurveKind(curveText)

  let guard = keygenTargetError(objectId = objectRef.objectId)
  if guard.isSome:
    stderr.writeLine guard.get()
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if exists.value:
    stderr.writeLine &"keygen refused: {objectIdHex(objectRef.objectId)} already exists"
    return 1

  let generated = se.generateEcKeyPair(
    objectId = objectRef.objectId,
    curve = curve,
    selectFirst = false
  )
  if not generated.ok:
    printSe050Error("WriteECKey failed", generated.error)
    return 1

  let after = se.objectExists(objectId = objectRef.objectId, selectFirst = false)
  if not after.ok:
    printSe050Error("Keygen verification failed", after.error)
    return 1

  if not after.value:
    stderr.writeLine &"WriteECKey returned success, but {objectIdHex(objectRef.objectId)} does not exist"
    return 1

  let typ = se.readObjectType(objectId = objectRef.objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType after keygen failed", typ.error)
    return 1

  let expectedType = expectedKeyPairType(curve)
  if typ.value.objectType != expectedType:
    stderr.writeLine &"keygen verification failed: expected type 0x{expectedType.toHex(2)}, got {typeText(typ.value.objectType)}"
    return 1

  echo &"{objectIdHex(objectRef.objectId)}: created"
  printResolvedObjectRef(objectRef)
  echo &"area: {areaLabel(objectRef.objectId)}"
  echo &"curve: {curveName(curve)}"
  echo &"type: {typeText(typ.value.objectType)}"
  echo &"transient: {transientText(typ.value.transientIndicator)}"

  result = 0

proc runPubkey(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string,
    outputPath: string,
    separator: string
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    stderr.writeLine &"pubkey failed: {objectIdHex(objectRef.objectId)} does not exist"
    return 1

  let typ = se.readObjectType(objectId = objectRef.objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType failed", typ.error)
    return 1

  if not typ.value.objectType.isReadableEcPublicObjectType():
    stderr.writeLine &"pubkey refused: {objectIdHex(objectRef.objectId)} is {typeText(typ.value.objectType)}, not an EC key pair/public key"
    return 2

  let publicKey = se.readPublicKey(objectId = objectRef.objectId, selectFirst = false)
  if not publicKey.ok:
    printSe050Error("ReadObject failed", publicKey.error)
    return 1

  if outputPath.strip().len > 0:
    writeFile(outputPath, bytesToRawString(publicKey.value))
    echo &"{objectIdHex(objectRef.objectId)}: public key written to {outputPath}"
    echo &"length: {publicKey.value.len}"
  else:
    echo bytesToHex(publicKey.value, separator = separator)

  result = 0

proc runDerive(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string,
    peerPublicPath: string,
    outputPath: string,
    separator: string
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  var peerPublicKey: seq[uint8]
  try:
    peerPublicKey = rawStringToBytes(readFile(peerPublicPath))
  except CatchableError as e:
    stderr.writeLine &"derive failed: cannot read peer public key file {peerPublicPath}: {e.msg}"
    return 1

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    stderr.writeLine &"derive failed: {objectIdHex(objectRef.objectId)} does not exist"
    return 1

  let typ = se.readObjectType(objectId = objectRef.objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType failed", typ.error)
    return 1

  if typ.value.objectType.isUnsupportedX25519DeriveObjectType():
    stderr.writeLine(
      "derive refused: X25519 derive is not supported on the tested " &
      "SE050/Applet 7.2.0 ECDHGenerateSharedSecret path; use P-256"
    )
    return 2

  if not typ.value.objectType.isDeriveKeyPairObjectType():
    stderr.writeLine &"derive refused: {objectIdHex(objectRef.objectId)} is {typeText(typ.value.objectType)}, not a supported EC key pair for derive"
    return 2

  let expectedPeerLen = expectedPeerPublicKeyLength(typ.value.objectType)
  if peerPublicKey.len != expectedPeerLen:
    stderr.writeLine &"derive refused: peer public key length mismatch for {typeText(typ.value.objectType)}: expected {expectedPeerLen} bytes, got {peerPublicKey.len}"
    return 2

  if typ.value.objectType in {Se050TypeEcKeyPair, Se050TypeEcKeyPairNistP256} and peerPublicKey.len > 0 and peerPublicKey[0] != 0x04'u8:
    stderr.writeLine "derive refused: P-256 peer public key must be an uncompressed point starting with 0x04"
    return 2

  let sharedSecret = se.deriveSharedSecret(
    objectId = objectRef.objectId,
    peerPublicKey = peerPublicKey,
    selectFirst = false
  )
  if not sharedSecret.ok:
    printSe050Error("ECDHGenerateSharedSecret failed", sharedSecret.error)
    return 1

  if outputPath.strip().len > 0:
    writeFile(outputPath, bytesToRawString(sharedSecret.value))
    echo &"{objectIdHex(objectRef.objectId)}: shared secret written to {outputPath}"
    printResolvedObjectRef(objectRef)
    echo &"length: {sharedSecret.value.len}"
  else:
    echo bytesToHex(sharedSecret.value, separator = separator)

  result = 0

proc runDelete(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)

  let guard = deleteTargetError(objectId = objectRef.objectId)
  if guard.isSome:
    stderr.writeLine guard.get()
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    echo &"{objectIdHex(objectRef.objectId)}: missing"
    return 1

  let deleted = se.deleteSecureObject(objectId = objectRef.objectId, selectFirst = false)
  if not deleted.ok:
    printSe050Error("DeleteSecureObject failed", deleted.error)
    return 1

  let after = se.objectExists(objectId = objectRef.objectId, selectFirst = false)
  if not after.ok:
    printSe050Error("Delete verification failed", after.error)
    return 1

  if after.value:
    stderr.writeLine &"DeleteSecureObject returned success, but {objectIdHex(objectRef.objectId)} still exists"
    return 1

  echo &"{objectIdHex(objectRef.objectId)}: deleted"
  result = 0

# =============================================================================
# Main
# =============================================================================

proc main(): int =
  var parser = newParser("se050ctl"):
    help("Low-level SE050 diagnostic and provisioning helper.")

    command("uid"):
      help("Read the SE050 unique ID object.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      flag("--colon", help = "Print UID as AA:BB:CC...")
      run:
        let separator = if opts.colon: ":" else: ""
        quit(runUid(opts.bus, opts.address, opts.debug, separator))

    command("random"):
      help("Generate random bytes using SE050 GetRandom.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("-l", "--len", required = true, help = "Random byte length, 1..255")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      flag("--colon", help = "Print bytes as AA:BB:CC...")
      run:
        let separator = if opts.colon: ":" else: ""
        quit(runRandom(opts.bus, opts.address, opts.debug, opts.len, separator))

    command("version"):
      help("Read SE050 applet version and feature configuration.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runVersion(opts.bus, opts.address, opts.debug))

    command("exists"):
      help("Check whether an SE050 Secure Object identifier exists.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name, currently: uid")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      flag("-q", "--quiet", help = "Do not print status; use exit code only")
      run:
        quit(runExists(opts.bus, opts.address, opts.debug, opts.id, opts.area, opts.index, opts.name, opts.quiet))

    command("info"):
      help("Read type and size information for an SE050 Secure Object identifier.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name, currently: uid")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runInfo(opts.bus, opts.address, opts.debug, opts.id, opts.area, opts.index, opts.name))

    command("list"):
      help("List visible SE050 Secure Object identifiers.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--filter", default = some("0xFF"), help = "SecureObjectType filter byte, default: 0xFF for all types")
      option("--area", default = some(""), help = "Only show IDs in an area: dev, customer, vendor, nxp, internal")
      flag("--annotate", help = "Print area and known-name columns")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runList(opts.bus, opts.address, opts.debug, opts.filter, opts.area, opts.annotate))

    command("keygen"):
      help("Generate a development SE050 key pair. Only area dev is allowed by this CLI.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Development Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area. For keygen, only dev is allowed")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name. Not useful for keygen, but rejected safely")
      option("--curve", default = some("p256"), help = "Curve name: p256 or x25519, default: p256")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runKeygen(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.area,
          opts.index,
          opts.name,
          opts.curve
        ))

    command("pubkey"):
      help("Read the public key from an SE050 EC key pair or EC public key object.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name. Must refer to an EC key object")
      option("-o", "--out", default = some(""), help = "Write raw public key bytes to this file instead of printing hex")
      flag("--colon", help = "Print bytes as AA:BB:CC... when not using --out")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        let separator = if opts.colon: ":" else: ""
        quit(runPubkey(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.area,
          opts.index,
          opts.name,
          opts.out,
          separator
        ))

    command("derive"):
      help("Derive an ECDH shared secret using an SE050 EC key pair and a peer public key file.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name. Must refer to a supported EC key pair")
      option("--peer-public", required = true, help = "Raw P-256 peer public key file, 65-byte uncompressed point")
      option("-o", "--out", default = some(""), help = "Write raw shared secret bytes to this file instead of printing hex")
      flag("--colon", help = "Print bytes as AA:BB:CC... when not using --out")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        let separator = if opts.colon: ":" else: ""
        quit(runDerive(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.area,
          opts.index,
          opts.name,
          opts.peer_public,
          opts.out,
          separator
        ))

    command("delete"):
      help("Delete an SE050 Secure Object identifier. Destructive operation; reserved ranges are always guarded.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name. Reserved names are rejected by delete guards")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runDelete(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.area,
          opts.index,
          opts.name
        ))

  try:
    parser.run()
    result = 0
  except UsageError:
    stderr.writeLine getCurrentExceptionMsg()
    result = 2
  except ValueError:
    stderr.writeLine &"error: {getCurrentExceptionMsg()}"
    result = 2

when isMainModule:
  quit(main())
