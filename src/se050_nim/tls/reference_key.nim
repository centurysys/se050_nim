# =============================================================================
# NXP OpenSSL Provider EC reference-key encoding
# =============================================================================
#
# NXP se05x-openssl-provider represents a Secure Element EC private key in a
# standard SEC1 ECPrivateKey structure whose private-key octets contain a
# provider-specific reference instead of the real private scalar. The actual
# public key and named-curve parameters remain ordinary EC key data.
#
# NXP documents the reference value as a key-length-sized field whose MSB side
# is padded with the 0x10..00 pattern and whose final 14 bytes contain:
#
#   Object ID (4) || magic (8) || key class (1) || reserved index (1)
#
# The Provider decoder likewise locates the Object ID relative to the end of
# the decoded private value, so the same layout applies to P-256 and P-384.
#
# This module performs no SE050 I/O and never handles real private key material.

import ../binary_encoding

# =============================================================================
# Constants
# =============================================================================

const
  P256ReferenceKeyDerSize* = 121
  P384ReferenceKeyDerSize* = 167

  NxpEcReferenceMagic = [
    0xA5'u8, 0xA6'u8, 0xB5'u8, 0xB6'u8,
    0xA5'u8, 0xA6'u8, 0xB5'u8, 0xB6'u8
  ]

  NxpEcReferenceKeyPairClass = 0x10'u8
  NxpEcReferenceKeyIndex = 0x00'u8
  NxpEcReferenceSuffixLength = 14

  # SEC1 ECPrivateKey, version 1, followed by a 32-byte privateKey OCTET STRING.
  P256EcPrivateKeyDerPrefix = [
    0x30'u8, 0x77'u8,
    0x02'u8, 0x01'u8, 0x01'u8,
    0x04'u8, 0x20'u8
  ]

  # [0] parameters: prime256v1 / secp256r1 / P-256.
  P256EcParametersDer = [
    0xA0'u8, 0x0A'u8,
    0x06'u8, 0x08'u8,
    0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8,
    0x3D'u8, 0x03'u8, 0x01'u8, 0x07'u8
  ]

  # [1] publicKey: BIT STRING containing 0x04 || X || Y.
  P256EcPublicKeyDerPrefix = [
    0xA1'u8, 0x44'u8,
    0x03'u8, 0x42'u8, 0x00'u8
  ]

  # SEC1 ECPrivateKey, version 1, followed by a 48-byte privateKey OCTET STRING.
  #
  # The complete sequence content is 164 bytes, so the outer SEQUENCE uses the
  # DER long-form length 0x81 0xA4.
  P384EcPrivateKeyDerPrefix = [
    0x30'u8, 0x81'u8, 0xA4'u8,
    0x02'u8, 0x01'u8, 0x01'u8,
    0x04'u8, 0x30'u8
  ]

  # [0] parameters: secp384r1 / NIST P-384, OID 1.3.132.0.34.
  P384EcParametersDer = [
    0xA0'u8, 0x07'u8,
    0x06'u8, 0x05'u8,
    0x2B'u8, 0x81'u8, 0x04'u8, 0x00'u8, 0x22'u8
  ]

  # [1] publicKey: BIT STRING containing the 97-byte 0x04 || X || Y point.
  P384EcPublicKeyDerPrefix = [
    0xA1'u8, 0x64'u8,
    0x03'u8, 0x62'u8, 0x00'u8
  ]

# =============================================================================
# Internal helpers
# =============================================================================

proc addBytes(dst: var seq[uint8], src: openArray[uint8]) =
  for b in src:
    dst.add(b)

proc validateUncompressedPublicKey(
    publicKey: openArray[uint8],
    expectedLength: int,
    curveName: string
) =
  if publicKey.len != expectedLength or publicKey[0] != 0x04'u8:
    raise newException(
      ValueError,
      "public key is not a " & $expectedLength &
        "-byte uncompressed NIST " & curveName & " point"
    )

proc referencePrivateValue(
    objectId: uint32,
    keyLength: int
): seq[uint8] =
  ## Encodes the NXP Provider reference inside a key-length-sized SEC1
  ## privateKey field.
  ##
  ## Big-endian layout:
  ##   0                       : 0x10 start marker
  ##   1 .. keyLength-15      : zero padding
  ##   keyLength-14 .. -11    : Object ID, big-endian
  ##   keyLength-10 .. -3     : 0xA5A6B5B6A5A6B5B6 magic
  ##   keyLength-2            : key class (0x10 = key pair)
  ##   keyLength-1            : reserved key index (0x00)
  if keyLength < NxpEcReferenceSuffixLength:
    raise newException(
      ValueError,
      "EC reference-key field is too short"
    )

  result = newSeq[uint8](keyLength)
  result[0] = 0x10'u8

  let suffixStart = keyLength - NxpEcReferenceSuffixLength
  result[suffixStart] = uint8((objectId shr 24) and 0xFF'u32)
  result[suffixStart + 1] = uint8((objectId shr 16) and 0xFF'u32)
  result[suffixStart + 2] = uint8((objectId shr 8) and 0xFF'u32)
  result[suffixStart + 3] = uint8(objectId and 0xFF'u32)

  for i, b in NxpEcReferenceMagic.pairs:
    result[suffixStart + 4 + i] = b

  result[suffixStart + 12] = NxpEcReferenceKeyPairClass
  result[suffixStart + 13] = NxpEcReferenceKeyIndex

proc appendPemBody(result: var string, base64Text: string) =
  const PemLineLength = 64

  var offset = 0
  while offset < base64Text.len:
    let lineEnd = min(offset + PemLineLength, base64Text.len)
    result.add(base64Text[offset ..< lineEnd])
    result.add('\n')
    offset = lineEnd

proc encodeReferenceKeyPem(der: openArray[uint8]): string =
  let base64Text = encodeBase64(der)

  result = "-----BEGIN EC PRIVATE KEY-----\n"
  result.appendPemBody(base64Text)
  result.add("-----END EC PRIVATE KEY-----\n")

# =============================================================================
# Public API
# =============================================================================

proc encodeP256ReferenceKeyDer*(
    objectId: uint32,
    publicKey: openArray[uint8]
): seq[uint8] =
  ## Builds an NXP OpenSSL Provider-compatible SEC1 P-256 reference key.
  ##
  ## The returned structure contains only the SE050 Object ID, provider magic,
  ## public key, and curve metadata. It does not contain the real private key.
  validateUncompressedPublicKey(
    publicKey,
    expectedLength = 65,
    curveName = "P-256"
  )

  let referenceValue = referencePrivateValue(objectId, 32)

  result = newSeqOfCap[uint8](P256ReferenceKeyDerSize)
  result.addBytes(P256EcPrivateKeyDerPrefix)
  result.addBytes(referenceValue)
  result.addBytes(P256EcParametersDer)
  result.addBytes(P256EcPublicKeyDerPrefix)
  result.addBytes(publicKey)

  doAssert result.len == P256ReferenceKeyDerSize

proc encodeP256ReferenceKeyPem*(
    objectId: uint32,
    publicKey: openArray[uint8]
): string =
  ## Builds a PEM-encoded SEC1 P-256 reference key for ordinary key-file APIs.
  result = encodeReferenceKeyPem(
    encodeP256ReferenceKeyDer(objectId, publicKey)
  )

proc encodeP384ReferenceKeyDer*(
    objectId: uint32,
    publicKey: openArray[uint8]
): seq[uint8] =
  ## Builds an NXP OpenSSL Provider-compatible SEC1 P-384 reference key.
  ##
  ## NXP's reference-key suffix remains at the least-significant end of the
  ## 48-byte privateKey field. The additional P-384 width is zero padding on
  ## the MSB side after the required 0x10 start marker.
  validateUncompressedPublicKey(
    publicKey,
    expectedLength = 97,
    curveName = "P-384"
  )

  let referenceValue = referencePrivateValue(objectId, 48)

  result = newSeqOfCap[uint8](P384ReferenceKeyDerSize)
  result.addBytes(P384EcPrivateKeyDerPrefix)
  result.addBytes(referenceValue)
  result.addBytes(P384EcParametersDer)
  result.addBytes(P384EcPublicKeyDerPrefix)
  result.addBytes(publicKey)

  doAssert result.len == P384ReferenceKeyDerSize

proc encodeP384ReferenceKeyPem*(
    objectId: uint32,
    publicKey: openArray[uint8]
): string =
  ## Builds a PEM-encoded SEC1 P-384 reference key for ordinary key-file APIs.
  result = encodeReferenceKeyPem(
    encodeP384ReferenceKeyDer(objectId, publicKey)
  )
