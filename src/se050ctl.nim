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
import se050_nim/secure_memory

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

  TlsPublicKeyFormat = enum
    tpkRaw,
    tpkSpkiDer

  FactoryCertificateFormat = enum
    fcfDer,
    fcfPem

  FactoryPublicKeyFormat = enum
    fpkSpkiDer,
    fpkPem

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

proc parseHexBytes(s: string): seq[uint8] =
  ## Parses compact or separator-delimited hexadecimal bytes.
  var source = s.strip()
  if source.startsWith("0x") or source.startsWith("0X"):
    source = source[2 .. ^1]

  var compact = ""
  for ch in source:
    if ch in {' ', ':', '-', '_'}:
      continue

    let isHex =
      (ch >= '0' and ch <= '9') or
      (ch >= 'a' and ch <= 'f') or
      (ch >= 'A' and ch <= 'F')
    if not isHex:
      raise newException(ValueError, &"invalid hexadecimal character: {ch}")

    compact.add(ch)

  if compact.len == 0:
    raise newException(ValueError, "hex byte string is empty")

  if (compact.len mod 2) != 0:
    raise newException(ValueError, "hex byte string must contain an even number of digits")

  result = newSeq[uint8](compact.len div 2)
  for i in 0 ..< result.len:
    result[i] = uint8(parseHexInt(compact[i * 2 .. i * 2 + 1]))

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

  let productionGuard = productionKittingMutationError(objectId, komDelete)
  if productionGuard.isSome:
    return productionGuard

  if not objectId.isDevelopmentObjectId():
    return some(
      &"delete refused: {objectIdHex(objectId)} is outside the se050ctl development range " &
      &"0x{DevelopmentStart.toHex(8)}..0x{DevelopmentEnd.toHex(8)}"
    )

  result = none(string)

proc keygenTargetError(objectId: uint32): Option[string] =
  if objectId == 0'u32:
    return some("object id 0x00000000 is not a valid key generation target")

  let productionGuard = productionKittingMutationError(objectId, komGenerate)
  if productionGuard.isSome:
    return productionGuard

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

proc parseTlsIdentityProfile(
    profileText: string,
    identityText: string,
    slotText: string
): TlsIdentityProfile =
  let kind =
    case profileText.strip().toLowerAscii()
    of "test":
      tipTest
    of "production":
      tipProduction
    else:
      raise newException(
        ValueError,
        &"TLS identity profile must be test or production: {profileText}"
      )

  let identity32 = parseIndex(identityText)
  if identity32 > uint32(TlsIdentityMaxIdentity):
    raise newException(
      ValueError,
      &"TLS identity index is out of range: {identityText} (max {TlsIdentityMaxIdentity})"
    )

  let slot =
    case slotText.strip().toUpperAscii()
    of "A":
      tisSlotA
    of "B":
      tisSlotB
    else:
      raise newException(
        ValueError,
        &"TLS identity slot must be A or B: {slotText}"
      )

  result = tlsIdentityProfile(kind, uint16(identity32), slot)
  if not result.isValid():
    raise newException(ValueError, "resolved TLS identity profile is invalid")

proc parseTlsPublicKeyFormat(value: string): TlsPublicKeyFormat =
  case value.strip().toLowerAscii()
  of "raw":
    result = tpkRaw
  of "spki-der", "spki", "der":
    result = tpkSpkiDer
  else:
    raise newException(
      ValueError,
      &"TLS public-key format must be raw or spki-der: {value}"
    )

proc parseFactoryCloudIdentityProfile(
    kindText: string,
    identityText: string
): FactoryCloudIdentityProfile =
  let kind =
    case kindText.strip().toLowerAscii()
    of "ecc", "p256", "ecc-p256", "prime256v1", "secp256r1":
      fciEccP256
    of "rsa", "rsa2048", "rsa-2048":
      fciRsa2048
    else:
      raise newException(
        ValueError,
        &"factory identity kind must be ecc or rsa: {kindText}"
      )

  let identity = parseIndex(identityText)
  if identity >= uint32(FactoryCloudIdentityCount):
    raise newException(
      ValueError,
      &"factory identity number must be 0 or 1: {identityText}"
    )

  result = factoryCloudIdentityProfile(kind, uint8(identity))

proc parseFactoryCertificateFormat(value: string): FactoryCertificateFormat =
  case value.strip().toLowerAscii()
  of "der":
    result = fcfDer
  of "pem":
    result = fcfPem
  else:
    raise newException(
      ValueError,
      &"factory certificate format must be der or pem: {value}"
    )

proc parseFactoryPublicKeyFormat(value: string): FactoryPublicKeyFormat =
  case value.strip().toLowerAscii()
  of "spki-der", "spki", "der":
    result = fpkSpkiDer
  of "pem":
    result = fpkPem
  else:
    raise newException(
      ValueError,
      &"factory public-key format must be spki-der or pem: {value}"
    )

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

proc readTlsImportPrivateKeyFile(path: string): SE[string] =
  ## Reads an external private-key file without invoking the openssl CLI.
  ##
  ## The returned string may contain PEM or DER bytes. The caller owns the
  ## returned mutable buffer and must clear it with secureZero() after use.
  let normalized = path.strip()
  if normalized.len == 0:
    return fail[string](
      seInvalidArgument,
      "TLS private-key input path is empty"
    )

  try:
    let data = readFile(normalized)
    if data.len == 0:
      return fail[string](
        seInvalidArgument,
        &"TLS private-key file is empty: {normalized}"
      )
    result = ok(data)
  except CatchableError as e:
    result = fail[string](
      seInvalidArgument,
      &"cannot read TLS private-key file {normalized}: {e.msg}"
    )

proc readTlsImportCertificateFile(path: string): SE[seq[uint8]] =
  ## Reads one matching X.509 certificate as DER or conventional PEM.
  ##
  ## Certificate parsing itself remains in the OpenSSL-backed import library;
  ## this helper only removes PEM framing and Base64 encoding when present.
  const
    PemBegin = "-----BEGIN CERTIFICATE-----"
    PemEnd = "-----END CERTIFICATE-----"

  let normalized = path.strip()
  if normalized.len == 0:
    return fail[seq[uint8]](
      seInvalidArgument,
      "TLS certificate input path is empty"
    )

  var raw: string
  try:
    raw = readFile(normalized)
  except CatchableError as e:
    return fail[seq[uint8]](
      seInvalidArgument,
      &"cannot read TLS certificate file {normalized}: {e.msg}"
    )

  if raw.len == 0:
    return fail[seq[uint8]](
      seInvalidArgument,
      &"TLS certificate file is empty: {normalized}"
    )

  let trimmed = raw.strip()
  if trimmed.startsWith(PemBegin):
    if not trimmed.endsWith(PemEnd):
      return fail[seq[uint8]](
        seInvalidArgument,
        &"TLS certificate PEM has invalid framing: {normalized}"
      )

    let bodyStart = PemBegin.len
    let bodyEnd = trimmed.len - PemEnd.len
    if bodyEnd <= bodyStart:
      return fail[seq[uint8]](
        seInvalidArgument,
        &"TLS certificate PEM body is empty: {normalized}"
      )

    var compact = ""
    for ch in trimmed[bodyStart ..< bodyEnd]:
      if ch in {' ', '\t', '\r', '\n'}:
        continue
      compact.add(ch)

    if compact.len == 0:
      return fail[seq[uint8]](
        seInvalidArgument,
        &"TLS certificate PEM body is empty: {normalized}"
      )

    let decoded = decodeBase64(compact)
    if not decoded.ok:
      return fail[seq[uint8]](
        decoded.error.kind,
        &"invalid TLS certificate PEM {normalized}: {decoded.error.message}",
        decoded.error.sw
      )

    return decoded

  if trimmed.startsWith("-----BEGIN"):
    return fail[seq[uint8]](
      seInvalidArgument,
      &"unsupported PEM object in TLS certificate file: {normalized}"
    )

  result = ok(rawStringToBytes(raw))

proc writeRawBytes(path: string, data: openArray[uint8], context: string): bool =
  try:
    writeFile(path, bytesToRawString(data))
    result = true
  except CatchableError as e:
    stderr.writeLine &"{context}: cannot write {path}: {e.msg}"
    result = false

proc readDerCertificateBundleFile(
    path: string,
    label: string
): SE[seq[seq[uint8]]] =
  ## Reads one or more concatenated DER X.509 certificates from a file.
  var raw: seq[uint8]
  try:
    raw = rawStringToBytes(readFile(path))
  except CatchableError as e:
    return fail[seq[seq[uint8]]](
      seInvalidArgument,
      &"cannot read {label} file {path}: {e.msg}"
    )

  let parsed = parseDerCertificateBundle(raw)
  if not parsed.ok:
    return fail[seq[seq[uint8]]](
      parsed.error.kind,
      &"invalid {label} file {path}: {parsed.error.message}",
      parsed.error.sw
    )

  result = parsed

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

proc printTlsIdentityInfo(info: TlsIdentityLiveInfo, created: Option[bool]) =
  let profile = info.profile
  let signedPolicy = info.semantics.attributes.policies[0]

  echo "TLS client key"
  echo &"  profile: {profile.name}"
  echo &"  identity: {profile.identity}"
  echo &"  slot: {profile.slot.slotName()}"
  echo &"  object id: {objectIdHex(profile.keyObjectId)}"
  echo &"  curve: {curveName(profile.curve)}"
  if created.isSome:
    let createdText = if created.get(): "yes" else: "no (reused)"
    echo &"  created: {createdText}"
  echo &"  type: {typeText(info.objectType)}"
  echo "  persistence: persistent (live ReadType)"
  echo &"  origin: {objectOriginName(info.semantics.attributes.origin)} (attested)"
  echo "  policy: SIGN + READ + DELETE"
  echo &"  policy header: 0x{signedPolicy.header.toHex(8)} (attested)"
  echo &"  public key: {bytesToHex(info.publicKey)}"
  echo "  public key match: live == attested"
  echo "  attestation certificate chain: verified"
  echo "  attestation signature: verified"

proc factoryObjectStatus(
    se: Se050Transport,
    objectId: uint32,
    selectFirst: bool
): SE[string] =
  let exists = se.objectExists(
    objectId = objectId,
    selectFirst = selectFirst
  )
  if not exists.ok:
    return fail[string](
      exists.error.kind,
      exists.error.message,
      exists.error.sw
    )

  if not exists.value:
    return ok("missing")

  let objectType = se.readObjectType(
    objectId = objectId,
    selectFirst = false
  )
  if not objectType.ok:
    return fail[string](
      objectType.error.kind,
      objectType.error.message,
      objectType.error.sw
    )

  result = ok(&"present, type {typeText(objectType.value.objectType)}")

proc runFactoryList(
    busText: string,
    addressText: string,
    debug: bool
): int =
  ## Shows the known NXP factory cloud credentials and attestation objects.
  let se = openAndRequestAtr(busText, addressText, debug)
  var selectFirst = true

  echo "NXP factory-provisioned objects"
  echo "cloud connection identities:"

  for profile in factoryCloudIdentityProfiles():
    let keyStatus = se.factoryObjectStatus(
      profile.keyObjectId,
      selectFirst = selectFirst
    )
    selectFirst = false
    if not keyStatus.ok:
      printSe050Error("factory-list key inspection failed", keyStatus.error)
      return 1

    let certificateStatus = se.factoryObjectStatus(
      profile.certificateObjectId,
      selectFirst = false
    )
    if not certificateStatus.ok:
      printSe050Error(
        "factory-list certificate inspection failed",
        certificateStatus.error
      )
      return 1

    echo &"  {profile.name}"
    echo &"    key {objectIdHex(profile.keyObjectId)}: {keyStatus.value}"
    echo &"    certificate {objectIdHex(profile.certificateObjectId)}: {certificateStatus.value}"

  echo "attestation identity:"
  let attestationKeyStatus = se.factoryObjectStatus(
    Se050AttestationKeyObjectId,
    selectFirst = selectFirst
  )
  selectFirst = false
  if not attestationKeyStatus.ok:
    printSe050Error(
      "factory-list attestation key inspection failed",
      attestationKeyStatus.error
    )
    return 1

  let attestationCertificateStatus = se.factoryObjectStatus(
    Se050AttestationCertificateObjectId,
    selectFirst = false
  )
  if not attestationCertificateStatus.ok:
    printSe050Error(
      "factory-list attestation certificate inspection failed",
      attestationCertificateStatus.error
    )
    return 1

  echo &"  key {objectIdHex(Se050AttestationKeyObjectId)}: {attestationKeyStatus.value}"
  echo &"  certificate {objectIdHex(Se050AttestationCertificateObjectId)}: {attestationCertificateStatus.value}"
  result = 0

proc requireFactoryIdentityObjects(
    se: Se050Transport,
    profile: FactoryCloudIdentityProfile
): SE[void] =
  let keyExists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = true
  )
  if not keyExists.ok:
    return fail[void](
      keyExists.error.kind,
      keyExists.error.message,
      keyExists.error.sw
    )
  if not keyExists.value:
    return fail[void](
      seInvalidArgument,
      &"factory key {objectIdHex(profile.keyObjectId)} does not exist on this SE050"
    )

  let certificateExists = se.objectExists(
    objectId = profile.certificateObjectId,
    selectFirst = false
  )
  if not certificateExists.ok:
    return fail[void](
      certificateExists.error.kind,
      certificateExists.error.message,
      certificateExists.error.sw
    )
  if not certificateExists.value:
    return fail[void](
      seInvalidArgument,
      &"factory certificate {objectIdHex(profile.certificateObjectId)} does not exist on this SE050"
    )

  result = ok()

proc runFactoryKeyRef(
    kindText: string,
    identityText: string
): int =
  ## Prints only the NXP OpenSSL Provider URI for shell/script consumption.
  let profile = parseFactoryCloudIdentityProfile(kindText, identityText)
  echo profile.opensslProviderKeyUri()
  result = 0

proc runFactoryCert(
    busText: string,
    addressText: string,
    debug: bool,
    kindText: string,
    identityText: string,
    formatText: string,
    outputPath: string
): int =
  let profile = parseFactoryCloudIdentityProfile(kindText, identityText)
  let outputFormat = parseFactoryCertificateFormat(formatText)
  if outputPath.strip().len == 0:
    raise newException(ValueError, "--out is required for factory-cert")

  let se = openAndRequestAtr(busText, addressText, debug)
  let available = se.requireFactoryIdentityObjects(profile)
  if not available.ok:
    printSe050Error("factory identity is unavailable", available.error)
    return 1

  let certificate = se.readFactoryCertificate(
    profile,
    selectFirst = false
  )
  if not certificate.ok:
    printSe050Error("factory certificate read failed", certificate.error)
    return 1

  case outputFormat
  of fcfDer:
    if not writeRawBytes(outputPath, certificate.value, "factory-cert"):
      return 1
  of fcfPem:
    try:
      writeFile(outputPath, factoryCertificateDerToPem(certificate.value))
    except CatchableError as e:
      stderr.writeLine &"factory-cert: cannot write {outputPath}: {e.msg}"
      return 1

  let formatName = if outputFormat == fcfDer: "der" else: "pem"
  echo &"{objectIdHex(profile.certificateObjectId)}: factory certificate written to {outputPath}"
  echo &"kind: {profile.kind.factoryCloudIdentityKindName()}"
  echo &"identity: {profile.identity}"
  echo &"format: {formatName}"
  echo &"DER length: {certificate.value.len}"
  result = 0

proc runFactoryPubkey(
    busText: string,
    addressText: string,
    debug: bool,
    kindText: string,
    identityText: string,
    formatText: string,
    outputPath: string
): int =
  let profile = parseFactoryCloudIdentityProfile(kindText, identityText)
  let outputFormat = parseFactoryPublicKeyFormat(formatText)
  if outputPath.strip().len == 0:
    raise newException(ValueError, "--out is required for factory-pubkey")

  let se = openAndRequestAtr(busText, addressText, debug)
  let available = se.requireFactoryIdentityObjects(profile)
  if not available.ok:
    printSe050Error("factory identity is unavailable", available.error)
    return 1

  let publicKey = se.readFactoryCertificatePublicKeySpkiDer(
    profile,
    selectFirst = false
  )
  if not publicKey.ok:
    printSe050Error("factory public-key extraction failed", publicKey.error)
    return 1

  case outputFormat
  of fpkSpkiDer:
    if not writeRawBytes(outputPath, publicKey.value, "factory-pubkey"):
      return 1
  of fpkPem:
    try:
      writeFile(outputPath, subjectPublicKeyInfoDerToPem(publicKey.value))
    except CatchableError as e:
      stderr.writeLine &"factory-pubkey: cannot write {outputPath}: {e.msg}"
      return 1

  let formatName = if outputFormat == fpkSpkiDer: "spki-der" else: "pem"
  echo &"{objectIdHex(profile.certificateObjectId)}: certificate public key written to {outputPath}"
  echo &"kind: {profile.kind.factoryCloudIdentityKindName()}"
  echo &"identity: {profile.identity}"
  echo &"format: {formatName}"
  echo &"length: {publicKey.value.len}"
  result = 0

proc runTlsKeyRef(
    profileText: string,
    identityText: string,
    slotText: string
): int =
  ## Prints only the NXP OpenSSL Provider URI for shell/script consumption.
  let profile = parseTlsIdentityProfile(profileText, identityText, slotText)
  echo profile.opensslProviderKeyUri()
  result = 0

proc runTlsKeyRefFile(
    busText: string,
    addressText: string,
    debug: bool,
    profileText: string,
    identityText: string,
    slotText: string,
    outputPath: string,
    imported: bool
): int =
  ## Exports one validated TLS identity as an NXP OpenSSL reference-key PEM.
  let profile = parseTlsIdentityProfile(profileText, identityText, slotText)
  if outputPath.strip().len == 0:
    raise newException(ValueError, "--out is required for tls-key-ref-file")

  let se = openAndRequestAtr(busText, addressText, debug)
  let written =
    if imported:
      se.writeImportedTlsReferenceKeyFile(profile, outputPath)
    else:
      se.writeTlsReferenceKeyFile(profile, outputPath)
  if not written.ok:
    printSe050Error("TLS reference-key export failed", written.error)
    return 1

  echo &"{objectIdHex(profile.keyObjectId)}: validated OpenSSL reference key written to {outputPath}"
  echo &"identity: {profile.identity}"
  echo &"slot: {profile.slot.slotName()}"
  echo "format: NXP P-256 reference-key PEM"
  let provisioning = if imported: "externally imported" else: "SE050 internally generated"
  echo &"provisioning: {provisioning}"
  echo "private key material: not exported"
  result = 0

proc runTlsKeyPubkey(
    busText: string,
    addressText: string,
    debug: bool,
    profileText: string,
    identityText: string,
    slotText: string,
    formatText: string,
    outputPath: string,
    imported: bool
): int =
  ## Exports the validated TLS identity public key for CSR/key matching.
  let profile = parseTlsIdentityProfile(profileText, identityText, slotText)
  let outputFormat = parseTlsPublicKeyFormat(formatText)
  if outputPath.strip().len == 0:
    raise newException(ValueError, "--out is required for tls-key-pubkey")

  let se = openAndRequestAtr(busText, addressText, debug)
  let exists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = true
  )
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    stderr.writeLine(
      &"tls-key-pubkey failed: {profile.name} identity {profile.identity} slot {profile.slot.slotName()} ({objectIdHex(profile.keyObjectId)}) does not exist"
    )
    return 1

  let inspected =
    if imported:
      inspectImportedTlsIdentity(se, profile)
    else:
      inspectTlsIdentity(se, profile)
  if not inspected.ok:
    printSe050Error("TLS identity validation failed", inspected.error)
    return 1

  let output =
    case outputFormat
    of tpkRaw:
      inspected.value.publicKey
    of tpkSpkiDer:
      p256PublicKeyToSpkiDer(inspected.value.publicKey)

  if not writeRawBytes(
      outputPath,
      output,
      "tls-key-pubkey"
  ):
    return 1

  let formatName = if outputFormat == tpkRaw: "raw" else: "spki-der"
  echo &"{objectIdHex(profile.keyObjectId)}: validated public key written to {outputPath}"
  echo &"identity: {profile.identity}"
  echo &"slot: {profile.slot.slotName()}"
  echo &"format: {formatName}"
  echo &"length: {output.len}"
  let provisioning = if imported: "externally imported" else: "SE050 internally generated"
  echo &"provisioning: {provisioning}"
  result = 0

proc runTlsKeyImport(
    busText: string,
    addressText: string,
    debug: bool,
    profileText: string,
    identityText: string,
    slotText: string,
    privateKeyPath: string,
    certificatePath: string
): int =
  ## Imports one externally generated P-256 TLS identity into an empty slot.
  ##
  ## All host-side key/certificate checks are completed by the library before
  ## it selects the SE050 applet or checks the target object. The source key
  ## file buffer is explicitly cleared before this command returns.
  let profile = parseTlsIdentityProfile(profileText, identityText, slotText)

  var loadedKey = readTlsImportPrivateKeyFile(privateKeyPath)
  if not loadedKey.ok:
    printSe050Error("TLS private-key load failed", loadedKey.error)
    return 2

  var encodedKey = move(loadedKey.value)
  defer:
    secureZero(encodedKey)

  let certificate = readTlsImportCertificateFile(certificatePath)
  if not certificate.ok:
    printSe050Error("TLS certificate load failed", certificate.error)
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)
  let imported = se.importP256TlsIdentity(
    profile = profile,
    encodedKey = encodedKey,
    certificateDer = certificate.value
  )
  if not imported.ok:
    printSe050Error("TLS key import failed", imported.error)
    return 1

  printTlsIdentityInfo(imported.value, none(bool))
  echo "  provisioning: externally imported P-256 private key"
  echo "  certificate/key match: verified before SE050 write"
  result = 0

proc runTlsKeygen(
    busText: string,
    addressText: string,
    debug: bool,
    profileText: string,
    identityText: string,
    slotText: string
): int =
  let profile = parseTlsIdentityProfile(profileText, identityText, slotText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = true
  )
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  var created = false
  if not exists.value:
    let generated = se.generateP256KeyPair(
      objectId = profile.keyObjectId,
      policy = profile.keyPolicy(),
      selectFirst = false
    )
    if not generated.ok:
      printSe050Error("TLS key generation failed", generated.error)
      return 1
    created = true

  let inspected = inspectTlsIdentity(se, profile)
  if not inspected.ok:
    if created:
      stderr.writeLine(
        &"TLS key was created at {objectIdHex(profile.keyObjectId)}, but post-generation validation failed. The object was left unchanged."
      )
    else:
      stderr.writeLine(
        &"tls-keygen refused to replace existing {objectIdHex(profile.keyObjectId)}; validation failed."
      )
    printSe050Error("TLS identity validation failed", inspected.error)
    return 1

  printTlsIdentityInfo(inspected.value, some(created))
  result = 0

proc runTlsKeyInfo(
    busText: string,
    addressText: string,
    debug: bool,
    profileText: string,
    identityText: string,
    slotText: string,
    imported: bool
): int =
  let profile = parseTlsIdentityProfile(profileText, identityText, slotText)
  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(
    objectId = profile.keyObjectId,
    selectFirst = true
  )
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    stderr.writeLine(
      &"tls-key-info failed: {profile.name} slot {profile.slot.slotName()} ({objectIdHex(profile.keyObjectId)}) does not exist"
    )
    return 1

  let inspected =
    if imported:
      inspectImportedTlsIdentity(se, profile)
    else:
      inspectTlsIdentity(se, profile)
  if not inspected.ok:
    printSe050Error("TLS identity validation failed", inspected.error)
    return 1

  printTlsIdentityInfo(inspected.value, none(bool))
  let provisioning = if imported: "externally imported" else: "SE050 internally generated"
  echo &"  provisioning: {provisioning}"
  result = 0

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

proc runCurveList(
    busText: string,
    addressText: string,
    debug: bool
): int =
  let se = openAndRequestAtr(busText, addressText, debug)

  let curves = se.readEcCurveList(selectFirst = true)
  if not curves.ok:
    printSe050Error("ReadECCurveList failed", curves.error)
    return 1

  echo "Weierstrass EC curves:"
  echo "  state describes current SE05x curve instantiation, not silicon capability"

  for index, indicator in curves.value.indicators:
    let curveId = uint8(index + 1)
    let state =
      case indicator
      of 0x01'u8: "not-set"
      of 0x02'u8: "set"
      else: "invalid"

    echo &"  0x{curveId.toHex(2)} {ecCurveName(curveId)}: {state}"

  echo "TLS import candidates:"
  for curveId in [
      Se050CurveNistP256,
      Se050CurveNistP384,
      Se050CurveNistP521
  ]:
    let instantiated = curves.value.isEcCurveInstantiated(curveId)
    if not instantiated.ok:
      echo &"  {ecCurveName(curveId)}: unavailable ({instantiated.error.message})"
    else:
      let state = if instantiated.value: "instantiated" else: "not instantiated"
      echo &"  {ecCurveName(curveId)}: {state}"

  result = 0

proc runCurveProvisionP384(
    busText: string,
    addressText: string,
    debug: bool,
    confirmed: bool
): int =
  ## Explicitly provisions the standard NIST P-384 curve domain parameters.
  ##
  ## Curve state is global SE05x state, not a disposable key object. Require an
  ## affirmative flag before opening the transport so accidental invocation of
  ## the command cannot mutate a device.
  if not confirmed:
    stderr.writeLine(
      "curve-provision-p384 refused: this changes persistent global SE05x curve state; " &
      "re-run with --yes after checking 'se050ctl curve-list'"
    )
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)

  let before = se.readEcCurveList(selectFirst = true)
  if not before.ok:
    printSe050Error("ReadECCurveList before P-384 provisioning failed", before.error)
    return 1

  let beforeState = before.value.ecCurveSetState(Se050CurveNistP384)
  if not beforeState.ok:
    printSe050Error("P-384 curve-state lookup failed", beforeState.error)
    return 1

  let beforeText =
    if beforeState.value == ecCurveSet:
      "set"
    else:
      "not-set"

  echo "NIST P-384 curve provisioning:"
  echo &"  before: {beforeText}"
  echo "  parameters: fixed standard secp384r1 / NIST P-384 values"

  let provisioned = se.provisionNistP384Curve(selectFirst = false)
  if not provisioned.ok:
    printSe050Error("NIST P-384 curve provisioning failed", provisioned.error)
    return 1

  case provisioned.value
  of ecCurveAlreadyInstantiated:
    echo "  action: none (already instantiated)"
  of ecCurveProvisioned:
    echo "  action: CreateECCurve + A/B/G/N/PRIME"

  let after = se.readEcCurveList(selectFirst = false)
  if not after.ok:
    printSe050Error("ReadECCurveList after P-384 provisioning failed", after.error)
    return 1

  let afterState = after.value.ecCurveSetState(Se050CurveNistP384)
  if not afterState.ok:
    printSe050Error("P-384 post-provision curve-state lookup failed", afterState.error)
    return 1

  let afterText =
    if afterState.value == ecCurveSet:
      "set"
    else:
      "not-set"

  echo &"  after: {afterText}"

  if afterState.value != ecCurveSet:
    stderr.writeLine("NIST P-384 provisioning did not leave the curve instantiated")
    return 1

  echo "NIST P-384 curve provisioning: OK"
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

proc runAttestationCert(
    busText: string,
    addressText: string,
    debug: bool,
    outputPath: string
): int =
  let se = openAndRequestAtr(busText, addressText, debug)

  let certificate = se.readAttestationCertificate(selectFirst = true)
  if not certificate.ok:
    printSe050Error("Read attestation certificate failed", certificate.error)
    return 1

  try:
    writeFile(outputPath, bytesToRawString(certificate.value))
  except CatchableError as e:
    stderr.writeLine &"attestation-cert failed: cannot write {outputPath}: {e.msg}"
    return 1

  echo &"{objectIdHex(Se050AttestationCertificateObjectId)}: attestation certificate written to {outputPath}"
  echo &"length: {certificate.value.len}"
  result = 0


proc runAttestRead(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string,
    freshnessText: string,
    outputPrefix: string
): int =
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  let freshness = parseHexBytes(freshnessText)
  if freshness.len != KittingFreshnessLength:
    stderr.writeLine &"attest-read requires exactly {KittingFreshnessLength} freshness bytes; got {freshness.len}"
    return 2

  let prefix = outputPrefix.strip()
  if prefix.len == 0:
    stderr.writeLine "attest-read requires a non-empty output prefix"
    return 2

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    stderr.writeLine &"attest-read failed: {objectIdHex(objectRef.objectId)} does not exist"
    return 1

  let typ = se.readObjectType(objectId = objectRef.objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType failed", typ.error)
    return 1

  if not typ.value.objectType.isReadableEcPublicObjectType():
    stderr.writeLine &"attest-read refused: {objectIdHex(objectRef.objectId)} is {typeText(typ.value.objectType)}, not an EC key pair/public key"
    return 2

  let attested = se.readObjectWithAttestation(
    objectId = objectRef.objectId,
    freshness = freshness,
    selectFirst = false
  )
  if not attested.ok:
    printSe050Error("ReadObject with Attestation failed", attested.error)
    return 1

  let commandPath = &"{prefix}.command.bin"
  let transmitPath = &"{prefix}.transmit-apdu.bin"
  let responsePath = &"{prefix}.response.bin"
  let signaturePath = &"{prefix}.signature.bin"
  let objectPath = &"{prefix}.object.bin"

  if not writeRawBytes(commandPath, attested.value.request.signedCommandApdu, "attest-read failed"):
    return 1
  if not writeRawBytes(transmitPath, attested.value.request.transmitApdu, "attest-read failed"):
    return 1
  if not writeRawBytes(responsePath, attested.value.response.rawResponseData, "attest-read failed"):
    return 1
  if not writeRawBytes(signaturePath, attested.value.response.signature, "attest-read failed"):
    return 1

  if attested.value.response.objectDataPresent:
    if not writeRawBytes(objectPath, attested.value.response.objectData, "attest-read failed"):
      return 1

  echo &"id: {objectIdHex(objectRef.objectId)}"
  printResolvedObjectRef(objectRef)
  echo &"type: {typeText(typ.value.objectType)}"
  echo &"freshness: {bytesToHex(freshness)}"
  echo &"chip uid: {bytesToHex(attested.value.response.chipId)}"
  echo &"object data present: {attested.value.response.objectDataPresent}"
  echo &"object data length: {attested.value.response.objectData.len}"
  echo &"attributes length: {attested.value.response.attributes.len}"
  echo &"object info: {bytesToHex(attested.value.response.objectInfo)}"
  echo &"timestamp: {bytesToHex(attested.value.response.timestamp)}"
  echo &"signature length: {attested.value.response.signature.len}"
  echo &"signed command: {commandPath}"
  echo &"transmitted APDU: {transmitPath}"
  echo &"raw response data: {responsePath}"
  echo &"signature: {signaturePath}"
  if attested.value.response.objectDataPresent:
    echo &"object data: {objectPath}"
  echo "verification: not performed by this diagnostic command"

  result = 0

proc runAttestVerify(
    busText: string,
    addressText: string,
    debug: bool,
    idText: string,
    areaText: string,
    indexText: string,
    nameText: string,
    freshnessText: string,
    trustAnchorsPath: string,
    intermediatesPath: string
): int =
  ## Verifies the live ReadObject-with-Attestation signature, validates the
  ## provisioned device certificate to explicit trust anchors, and confirms
  ## that the certificate public key matches the attestation key object.
  let objectRef = resolveObjectRef(idText, areaText, indexText, nameText)
  let profileMatch = kittingProfileForObjectId(objectRef.objectId)
  if profileMatch.isNone:
    stderr.writeLine &"attest-verify refused: {objectIdHex(objectRef.objectId)} is not a configured kitting key object"
    return 2
  let profile = profileMatch.get()

  let freshness = parseHexBytes(freshnessText)
  if freshness.len != KittingFreshnessLength:
    stderr.writeLine &"attest-verify requires exactly {KittingFreshnessLength} freshness bytes; got {freshness.len}"
    return 2

  let trustAnchors = readDerCertificateBundleFile(
    trustAnchorsPath,
    "trust-anchor bundle"
  )
  if not trustAnchors.ok:
    printSe050Error("Load trust anchors failed", trustAnchors.error)
    return 2

  var intermediates: seq[seq[uint8]] = @[]
  if intermediatesPath.strip().len > 0:
    let loadedIntermediates = readDerCertificateBundleFile(
      intermediatesPath,
      "intermediate-certificate bundle"
    )
    if not loadedIntermediates.ok:
      printSe050Error("Load intermediate certificates failed", loadedIntermediates.error)
      return 2
    intermediates = loadedIntermediates.value

  let se = openAndRequestAtr(busText, addressText, debug)

  let exists = se.objectExists(objectId = objectRef.objectId, selectFirst = true)
  if not exists.ok:
    printSe050Error("CheckObjectExists failed", exists.error)
    return 1

  if not exists.value:
    stderr.writeLine &"attest-verify failed: {objectIdHex(objectRef.objectId)} does not exist"
    return 1

  let typ = se.readObjectType(objectId = objectRef.objectId, selectFirst = false)
  if not typ.ok:
    printSe050Error("ReadType failed", typ.error)
    return 1

  if not typ.value.objectType.isReadableEcPublicObjectType():
    stderr.writeLine &"attest-verify refused: {objectIdHex(objectRef.objectId)} is {typeText(typ.value.objectType)}, not an EC key pair/public key"
    return 2

  let certificate = se.readAttestationCertificate(selectFirst = false)
  if not certificate.ok:
    printSe050Error("Read attestation certificate failed", certificate.error)
    return 1

  let chain = verifyCertificateChain(
    certificate.value,
    trustAnchors.value,
    intermediates
  )
  if not chain.ok:
    printSe050Error("Attestation certificate chain verification failed", chain.error)
    return 1

  let certificatePublicKey = extractCertificateEcPublicKey(certificate.value)
  if not certificatePublicKey.ok:
    printSe050Error("Attestation certificate public-key extraction failed", certificatePublicKey.error)
    return 1

  let provisionedPublicKey = se.readPublicKey(
    objectId = Se050AttestationKeyObjectId,
    selectFirst = false
  )
  if not provisionedPublicKey.ok:
    printSe050Error("Read attestation key public part failed", provisionedPublicKey.error)
    return 1

  if certificatePublicKey.value != provisionedPublicKey.value:
    stderr.writeLine(
      "attest-verify failed: certificate public key does not match " &
      objectIdHex(Se050AttestationKeyObjectId)
    )
    return 1

  let attested = se.readObjectWithAttestation(
    objectId = objectRef.objectId,
    freshness = freshness,
    selectFirst = false
  )
  if not attested.ok:
    printSe050Error("ReadObject with Attestation failed", attested.error)
    return 1

  let verified = verifyAttestationSignature(attested.value, certificate.value)
  if not verified.ok:
    printSe050Error("Attestation signature verification failed", verified.error)
    return 1

  let semantics = verifyKittingAttestationSemantics(attested.value, profile)
  if not semantics.ok:
    printSe050Error("Kitting attestation semantic validation failed", semantics.error)
    return 1

  let signedPolicy = semantics.value.attributes.policies[0]

  echo &"id: {objectIdHex(objectRef.objectId)}"
  printResolvedObjectRef(objectRef)
  echo &"type: {typeText(typ.value.objectType)}"
  echo &"freshness: {bytesToHex(freshness)}"
  echo &"chip uid: {bytesToHex(attested.value.response.chipId)}"
  echo &"certificate sha256: {bytesToHex(verified.value.certificateSha256)}"
  echo &"certificate key matches {objectIdHex(Se050AttestationKeyObjectId)}: yes"
  echo &"certificate trust anchors: {chain.value.trustAnchorCount}"
  echo &"certificate intermediates: {chain.value.intermediateCount}"
  echo "certificate trust chain: valid"
  echo "attestation signature: valid"
  echo &"kitting profile: {semantics.value.profile.name}"
  echo &"attribute object id: {objectIdHex(semantics.value.attributes.objectId)}"
  echo &"attribute object type: 0x{semantics.value.attributes.objectType.toHex(2)}"
  echo &"attribute auth: {objectAuthenticationIndicatorName(semantics.value.attributes.authAttribute)}"
  echo &"attribute owner auth object: {objectIdHex(semantics.value.attributes.ownerAuthObjectId)}"
  echo &"attribute origin: {objectOriginName(semantics.value.attributes.origin)}"
  echo &"attribute version: 0x{semantics.value.attributes.objectVersion.toHex(8)}"
  echo &"policy count: {semantics.value.attributes.policies.len}"
  echo &"policy auth object: {objectIdHex(signedPolicy.authObjectId)}"
  echo &"policy header: 0x{signedPolicy.header.toHex(8)}"
  echo &"object size: {semantics.value.objectSize}"
  echo "kitting semantics: valid"

  result = 0

proc runKittingVerify(
    busText: string,
    addressText: string,
    debug: bool,
    inputPath: string,
    profileText: string
): int =
  ## Selects this board's CSV row, performs every offline trust check, and then
  ## confirms that the live SE050 UID, object type, persistence, and public key
  ## still match the attested record.
  let profileMatch = kittingProfileForName(profileText.strip().toLowerAscii())
  if profileMatch.isNone:
    stderr.writeLine &"kitting-verify refused: unknown profile {profileText}"
    return 2
  let profile = profileMatch.get()

  let boardSerial = readBoardSerialNumber()
  if not boardSerial.ok:
    printSe050Error("Read board serial number failed", boardSerial.error)
    return 2

  var csvText: string
  try:
    csvText = readFile(inputPath)
  except CatchableError as e:
    stderr.writeLine &"kitting-verify failed: cannot read CSV file {inputPath}: {e.msg}"
    return 2

  let trustAnchors = nxpAttestationTrustAnchors()
  let intermediates = nxpAttestationIntermediates()

  let verified = verifyKittingCsvRecord(
    csvText = csvText,
    serialNumber = boardSerial.value,
    profileKind = profile.kind,
    trustAnchorsDer = trustAnchors,
    intermediatesDer = intermediates
  )
  if not verified.ok:
    printSe050Error("Kitting CSV verification failed", verified.error)
    return 1

  let se = openAndRequestAtr(busText, addressText, debug)

  let liveUidRaw = se.readUidRaw(selectFirst = true)
  if not liveUidRaw.ok:
    printSe050Error("Read live SE050 UID failed", liveUidRaw.error)
    return 6

  var liveUid = newSeq[uint8](Se050UidLength)
  for index, value in liveUidRaw.value:
    liveUid[index] = value

  let objectType = se.readObjectType(
    objectId = verified.value.record.keyObjectId,
    selectFirst = false
  )
  if not objectType.ok:
    printSe050Error("Read live kitting key type failed", objectType.error)
    return 6

  let publicKey = se.readPublicKey(
    objectId = verified.value.record.keyObjectId,
    selectFirst = false
  )
  if not publicKey.ok:
    printSe050Error("Read live kitting public key failed", publicKey.error)
    return 6

  let local = verifyLocalKittingIdentity(
    verified = verified.value,
    boardSerialNumber = boardSerial.value,
    liveSe050Uid = liveUid,
    liveObjectType = objectType.value.objectType,
    liveTransientIndicator = objectType.value.transientIndicator,
    livePublicKey = publicKey.value
  )
  if not local.ok:
    printSe050Error("Local kitting identity verification failed", local.error)
    return 5

  let signedPolicy = local.value.verified.semantics.attributes.policies[0]

  echo &"serialno: {local.value.boardSerialNumber}"
  echo &"profile: {profile.name}"
  echo &"created at: {local.value.verified.record.createdAt}"
  echo &"key role: {local.value.verified.record.keyRole}"
  echo &"key object id: {objectIdHex(local.value.verified.record.keyObjectId)}"
  echo &"SE050 UID: {bytesToHex(local.value.liveSe050Uid)}"
  echo &"certificate sha256: {bytesToHex(local.value.verified.signature.certificateSha256)}"
  echo &"certificate trust anchors: {local.value.verified.certificateChain.trustAnchorCount}"
  echo &"certificate intermediates: {local.value.verified.certificateChain.intermediateCount}"
  echo "certificate trust chain: valid"
  echo "attestation signature: valid"
  echo &"attribute origin: {objectOriginName(local.value.verified.semantics.attributes.origin)}"
  echo &"policy header: 0x{signedPolicy.header.toHex(8)}"
  echo &"live object type: {typeText(local.value.liveObjectType)}"
  echo "live object persistence: persistent"
  echo "local board serial: match"
  echo "local SE050 UID: match"
  echo "local public key: match"
  echo "kitting record: valid"

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

    command("curve-list"):
      help("Read the currently instantiated SE05x Weierstrass EC curves.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runCurveList(opts.bus, opts.address, opts.debug))

    command("curve-provision-p384"):
      help("Provision the fixed standard NIST P-384 curve parameters when currently not-set.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("--yes", help = "Confirm modification of persistent global SE05x curve state")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runCurveProvisionP384(
          opts.bus,
          opts.address,
          opts.debug,
          opts.yes
        ))

    command("version"):
      help("Read SE050 applet version and feature configuration.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runVersion(opts.bus, opts.address, opts.debug))

    command("factory-list"):
      help("Show known NXP factory-provisioned cloud and attestation objects.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runFactoryList(opts.bus, opts.address, opts.debug))

    command("factory-key-ref"):
      help("Print the NXP OpenSSL Provider URI for one factory cloud identity.")
      option("--kind", default = some("ecc"), help = "Factory identity kind: ecc or rsa, default: ecc")
      option("--identity", default = some("0"), help = "Factory identity number: 0 or 1, default: 0")
      run:
        quit(runFactoryKeyRef(opts.kind, opts.identity))

    command("factory-cert"):
      help("Export an NXP factory-provisioned cloud identity certificate.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--kind", default = some("ecc"), help = "Factory identity kind: ecc or rsa, default: ecc")
      option("--identity", default = some("0"), help = "Factory identity number: 0 or 1, default: 0")
      option("--format", default = some("pem"), help = "Output format: pem or der, default: pem")
      option("--out", required = true, help = "Output file")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runFactoryCert(
          opts.bus,
          opts.address,
          opts.debug,
          opts.kind,
          opts.identity,
          opts.format,
          opts.out
        ))

    command("factory-pubkey"):
      help("Export the public key from an NXP factory cloud certificate.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--kind", default = some("ecc"), help = "Factory identity kind: ecc or rsa, default: ecc")
      option("--identity", default = some("0"), help = "Factory identity number: 0 or 1, default: 0")
      option("--format", default = some("spki-der"), help = "Output format: spki-der or pem, default: spki-der")
      option("--out", required = true, help = "Output file")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runFactoryPubkey(
          opts.bus,
          opts.address,
          opts.debug,
          opts.kind,
          opts.identity,
          opts.format,
          opts.out
        ))

    command("tls-key-ref"):
      help("Print the NXP OpenSSL Provider URI for one TLS identity slot.")
      option("--profile", required = true, help = "TLS identity profile: test or production")
      option("--identity", default = some("0"), help = "TLS identity number, default: 0")
      option("--slot", required = true, help = "TLS identity slot: A or B")
      run:
        quit(runTlsKeyRef(
          opts.profile,
          opts.identity,
          opts.slot
        ))

    command("tls-key-ref-file"):
      help("Export an attestation-validated TLS identity as an NXP OpenSSL reference-key PEM.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--profile", required = true, help = "TLS identity profile: test or production")
      option("--identity", default = some("0"), help = "TLS identity number, default: 0")
      option("--slot", required = true, help = "TLS identity slot: A or B")
      option("--out", required = true, help = "Output reference-key PEM file; existing paths are not overwritten")
      flag("--imported", help = "Require an externally imported TLS key instead of the default internally generated key")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runTlsKeyRefFile(
          opts.bus,
          opts.address,
          opts.debug,
          opts.profile,
          opts.identity,
          opts.slot,
          opts.out,
          opts.imported
        ))

    command("tls-key-pubkey"):
      help("Export an attestation-validated TLS identity public key.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--profile", required = true, help = "TLS identity profile: test or production")
      option("--identity", default = some("0"), help = "TLS identity number, default: 0")
      option("--slot", required = true, help = "TLS identity slot: A or B")
      option("--format", default = some("spki-der"), help = "Output format: raw or spki-der, default: spki-der")
      option("--out", required = true, help = "Output file")
      flag("--imported", help = "Require an externally imported TLS key instead of the default internally generated key")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runTlsKeyPubkey(
          opts.bus,
          opts.address,
          opts.debug,
          opts.profile,
          opts.identity,
          opts.slot,
          opts.format,
          opts.out,
          opts.imported
        ))

    command("tls-key-import"):
      help("Import an external P-256 private key into one empty SE050 TLS identity slot.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--profile", required = true, help = "TLS identity profile: test or production")
      option("--identity", default = some("0"), help = "TLS identity number, default: 0")
      option("--slot", required = true, help = "TLS identity slot: A or B")
      option("--key", required = true, help = "External unencrypted P-256 private key file in PEM or DER")
      option("--cert", required = true, help = "Matching X.509 certificate file in PEM or DER")
      flag("-d", "--debug", help = "Print non-sensitive T=1 over I2C frames; key-import frames are redacted")
      run:
        quit(runTlsKeyImport(
          opts.bus,
          opts.address,
          opts.debug,
          opts.profile,
          opts.identity,
          opts.slot,
          opts.key,
          opts.cert
        ))

    command("tls-keygen"):
      help("Create or validate one fixed SE050 TLS client identity A/B key.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--profile", required = true, help = "TLS identity profile: test or production")
      option("--identity", default = some("0"), help = "TLS identity number, default: 0")
      option("--slot", required = true, help = "TLS identity slot: A or B")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runTlsKeygen(
          opts.bus,
          opts.address,
          opts.debug,
          opts.profile,
          opts.identity,
          opts.slot
        ))

    command("tls-key-info"):
      help("Validate and show one fixed SE050 TLS client identity A/B key.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--profile", required = true, help = "TLS identity profile: test or production")
      option("--identity", default = some("0"), help = "TLS identity number, default: 0")
      option("--slot", required = true, help = "TLS identity slot: A or B")
      flag("--imported", help = "Require an externally imported TLS key instead of the default internally generated key")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runTlsKeyInfo(
          opts.bus,
          opts.address,
          opts.debug,
          opts.profile,
          opts.identity,
          opts.slot,
          opts.imported
        ))

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

    command("attestation-cert"):
      help("Read the NXP-provisioned SE050 device attestation certificate.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("-o", "--out", required = true, help = "Write the DER certificate to this file")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runAttestationCert(
          opts.bus,
          opts.address,
          opts.debug,
          opts.out
        ))

    command("attest-read"):
      help("Read an SE050 EC public key with NXP attestation and capture raw verification inputs.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name. Must refer to an EC key object")
      option("--freshness", required = true, help = "16-byte freshness as hexadecimal text")
      option("-o", "--out-prefix", required = true, help = "Output path prefix for captured binary data")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runAttestRead(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.area,
          opts.index,
          opts.name,
          opts.freshness,
          opts.out_prefix
        ))

    command("attest-verify"):
      help("Verify a configured kitting key, its NXP certificate chain, attestation signature, and signed object attributes.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--id", default = some(""), help = "Secure Object ID in hex, e.g. 0x30000100")
      option("--area", default = some(""), help = "Object area: dev, customer, vendor, nxp, internal")
      option("--index", default = some(""), help = "Area-relative object index, decimal or 0x-prefixed hex")
      option("--name", default = some(""), help = "Known object name. Must refer to an EC key object")
      option("--freshness", required = true, help = "16-byte freshness as hexadecimal text")
      option("--trust-anchors", required = true, help = "DER file containing one or more trusted CA certificates")
      option("--intermediates", default = some(""), help = "Optional DER file containing concatenated intermediate certificates")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runAttestVerify(
          opts.bus,
          opts.address,
          opts.debug,
          opts.id,
          opts.area,
          opts.index,
          opts.name,
          opts.freshness,
          opts.trust_anchors,
          opts.intermediates
        ))

    command("kitting-verify"):
      help("Verify this unit against an attested multi-device kitting CSV.")
      option("-b", "--bus", required = true, help = "I2C bus number, e.g. 0 for /dev/i2c-0")
      option("-a", "--address", default = some("0x48"), help = "SE050 I2C address in hex, default: 0x48")
      option("--input", required = true, help = "Multi-device kitting CSV file")
      option("--profile", default = some("production"), help = "Kitting profile: production or test, default: production")
      flag("-d", "--debug", help = "Print T=1 over I2C frames")
      run:
        quit(runKittingVerify(
          opts.bus,
          opts.address,
          opts.debug,
          opts.input,
          opts.profile
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
