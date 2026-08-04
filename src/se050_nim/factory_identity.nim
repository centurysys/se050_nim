# =============================================================================
# NXP factory-provisioned cloud identities
# =============================================================================
#
# SE050 variants may contain NXP-provisioned cloud connection credentials.
# These credentials are useful for quick onboarding because the private key and
# matching X.509 certificate already exist before customer provisioning.
#
# This module deliberately treats the factory objects as read-only. It provides
# a catalog, certificate readout, public-key extraction from the certificate,
# and OpenSSL Provider references. Creation, deletion, or replacement of NXP
# factory objects does not belong here.

import std/base64
import std/strformat
import std/strutils

import ./apdu
import ./errors
import ./transport
import ./objects
import ./x509_verify
import ./attestation/cert
import ./tls/openssl

# =============================================================================
# Constants
# =============================================================================

const
  FactoryCloudIdentityCount* = 2'u8

  # NXP-provisioned ECC P-256 cloud connection credentials.
  Se050FactoryCloudEcc0KeyObjectId* = 0xF0000100'u32
  Se050FactoryCloudEcc0CertificateObjectId* = 0xF0000101'u32
  Se050FactoryCloudEcc1KeyObjectId* = 0xF0000102'u32
  Se050FactoryCloudEcc1CertificateObjectId* = 0xF0000103'u32

  # NXP-provisioned RSA-2048 cloud connection credentials.
  Se050FactoryCloudRsa0KeyObjectId* = 0xF0000110'u32
  Se050FactoryCloudRsa0CertificateObjectId* = 0xF0000111'u32
  Se050FactoryCloudRsa1KeyObjectId* = 0xF0000112'u32
  Se050FactoryCloudRsa1CertificateObjectId* = 0xF0000113'u32

# =============================================================================
# Types
# =============================================================================

type
  FactoryCloudIdentityKind* = enum
    fciEccP256,
    fciRsa2048

  FactoryCloudIdentityProfile* = object
    ## One known NXP factory-provisioned cloud connection credential pair.
    kind*: FactoryCloudIdentityKind
    identity*: uint8
    name*: string
    keyObjectId*: uint32
    certificateObjectId*: uint32

# =============================================================================
# Profile mapping
# =============================================================================

proc factoryCloudIdentityKindName*(kind: FactoryCloudIdentityKind): string =
  case kind
  of fciEccP256:
    result = "ecc-p256"
  of fciRsa2048:
    result = "rsa-2048"

proc factoryCloudIdentityProfile*(
    kind: FactoryCloudIdentityKind,
    identity: uint8
): FactoryCloudIdentityProfile =
  ## Resolves one documented NXP factory cloud-identity slot.
  if identity >= FactoryCloudIdentityCount:
    raise newException(
      ValueError,
      &"factory cloud identity must be 0 or 1: {identity}"
    )

  result.kind = kind
  result.identity = identity
  result.name = &"{kind.factoryCloudIdentityKindName()} identity {identity}"

  case kind
  of fciEccP256:
    case identity
    of 0'u8:
      result.keyObjectId = Se050FactoryCloudEcc0KeyObjectId
      result.certificateObjectId = Se050FactoryCloudEcc0CertificateObjectId
    of 1'u8:
      result.keyObjectId = Se050FactoryCloudEcc1KeyObjectId
      result.certificateObjectId = Se050FactoryCloudEcc1CertificateObjectId
    else:
      discard
  of fciRsa2048:
    case identity
    of 0'u8:
      result.keyObjectId = Se050FactoryCloudRsa0KeyObjectId
      result.certificateObjectId = Se050FactoryCloudRsa0CertificateObjectId
    of 1'u8:
      result.keyObjectId = Se050FactoryCloudRsa1KeyObjectId
      result.certificateObjectId = Se050FactoryCloudRsa1CertificateObjectId
    else:
      discard

proc factoryCloudIdentityProfiles*(): array[4, FactoryCloudIdentityProfile] =
  result = [
    factoryCloudIdentityProfile(fciEccP256, 0'u8),
    factoryCloudIdentityProfile(fciEccP256, 1'u8),
    factoryCloudIdentityProfile(fciRsa2048, 0'u8),
    factoryCloudIdentityProfile(fciRsa2048, 1'u8)
  ]

proc isValid*(profile: FactoryCloudIdentityProfile): bool =
  if profile.identity >= FactoryCloudIdentityCount:
    return false

  let expected = factoryCloudIdentityProfile(profile.kind, profile.identity)
  result =
    profile.name == expected.name and
    profile.keyObjectId == expected.keyObjectId and
    profile.certificateObjectId == expected.certificateObjectId

proc opensslProviderKeyUri*(profile: FactoryCloudIdentityProfile): string =
  ## Returns the NXP OpenSSL Provider URI for the factory private-key object.
  if not profile.isValid():
    raise newException(ValueError, "factory cloud identity profile is invalid")
  result = opensslProviderKeyUri(profile.keyObjectId)

# =============================================================================
# PEM helpers
# =============================================================================

proc bytesToString(data: openArray[uint8]): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc derToPem(label: string, der: openArray[uint8]): string =
  if der.len == 0:
    raise newException(ValueError, "DER data must not be empty")

  let encoded = base64.encode(bytesToString(der))
  result = &"-----BEGIN {label}-----\n"

  var offset = 0
  while offset < encoded.len:
    let lineEnd = min(offset + 64, encoded.len)
    result.add(encoded[offset ..< lineEnd])
    result.add('\n')
    offset = lineEnd

  result.add(&"-----END {label}-----\n")

proc factoryCertificateDerToPem*(certificateDer: openArray[uint8]): string =
  result = derToPem("CERTIFICATE", certificateDer)

proc subjectPublicKeyInfoDerToPem*(publicKeyDer: openArray[uint8]): string =
  result = derToPem("PUBLIC KEY", publicKeyDer)

# =============================================================================
# SE050 access
# =============================================================================

proc readFactoryCertificate*(
    se: Se050Transport,
    profile: FactoryCloudIdentityProfile,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Reads the factory-provisioned X.509 certificate for one cloud identity.
  ##
  ## Some factory BinaryFile objects may have zero padding after the encoded
  ## certificate, so the DER SEQUENCE length is used to trim the returned value.
  if not profile.isValid():
    return fail[seq[uint8]](
      seInvalidArgument,
      "factory cloud identity profile is invalid"
    )

  if selectFirst:
    let selected = se.selectApplet()
    if not selected.ok:
      return fail[seq[uint8]](
        selected.error.kind,
        selected.error.message,
        selected.error.sw
      )

  let objectType = se.readObjectType(
    objectId = profile.certificateObjectId,
    selectFirst = false
  )
  if not objectType.ok:
    return fail[seq[uint8]](
      objectType.error.kind,
      objectType.error.message,
      objectType.error.sw
    )

  if objectType.value.objectType != Se050TypeBinaryFile:
    return fail[seq[uint8]](
      seInvalidResponse,
      &"factory certificate object 0x{profile.certificateObjectId.toHex(8)} is not a BINARY_FILE"
    )

  let objectSize = se.readObjectSize(
    objectId = profile.certificateObjectId,
    selectFirst = false
  )
  if not objectSize.ok:
    return fail[seq[uint8]](
      objectSize.error.kind,
      objectSize.error.message,
      objectSize.error.sw
    )

  let objectData = se.readBinaryObject(
    objectId = profile.certificateObjectId,
    objectSize = objectSize.value,
    selectFirst = false
  )
  if not objectData.ok:
    return fail[seq[uint8]](
      objectData.error.kind,
      objectData.error.message,
      objectData.error.sw
    )

  let certificate = extractAttestationCertificateDer(objectData.value)
  if not certificate.ok:
    return fail[seq[uint8]](
      certificate.error.kind,
      certificate.error.message.replace(
        "attestation certificate",
        "factory certificate"
      ),
      certificate.error.sw
    )

  result = certificate

proc readFactoryCertificatePublicKeySpkiDer*(
    se: Se050Transport,
    profile: FactoryCloudIdentityProfile,
    selectFirst: bool = true
): SE[seq[uint8]] =
  ## Reads the factory certificate and extracts its SubjectPublicKeyInfo DER.
  let certificate = se.readFactoryCertificate(profile, selectFirst = selectFirst)
  if not certificate.ok:
    return fail[seq[uint8]](
      certificate.error.kind,
      certificate.error.message,
      certificate.error.sw
    )

  result = extractCertificatePublicKeySpkiDer(certificate.value)
