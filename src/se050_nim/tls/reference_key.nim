# =============================================================================
# NXP OpenSSL Provider EC reference-key encoding
# =============================================================================
#
# NXP se05x-openssl-provider represents a Secure Element EC private key in a
# standard SEC1 ECPrivateKey structure whose private-key octets contain a
# provider-specific reference instead of the real private scalar. The actual
# public key and prime256v1 parameters remain ordinary EC key data.
#
# This module implements only the currently required P-256 key-pair format.
# It performs no SE050 I/O and never handles private key material.

import ../binary_encoding

# =============================================================================
# Constants
# =============================================================================

const
  P256ReferenceKeyDerSize* = 121

  NxpEcReferenceMagic = [
    0xA5'u8, 0xA6'u8, 0xB5'u8, 0xB6'u8,
    0xA5'u8, 0xA6'u8, 0xB5'u8, 0xB6'u8
  ]

  NxpEcReferenceKeyPairClass = 0x10'u8
  NxpEcReferenceKeyIndex = 0x00'u8

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

# =============================================================================
# Internal helpers
# =============================================================================

proc addBytes(dst: var seq[uint8], src: openArray[uint8]) =
  for b in src:
    dst.add(b)

proc validateP256PublicKey(publicKey: openArray[uint8]) =
  if publicKey.len != 65 or publicKey[0] != 0x04'u8:
    raise newException(
      ValueError,
      "public key is not a 65-byte uncompressed NIST P-256 point"
    )

proc p256ReferencePrivateValue(objectId: uint32): array[32, uint8] =
  ## Encodes the provider reference inside the SEC1 privateKey field.
  ##
  ## Layout documented by NXP for a 256-bit EC reference key:
  ##   0      : 0x10 marker
  ##   1..17  : zero padding
  ##   18..21 : Object ID, big-endian
  ##   22..29 : 0xA5A6B5B6A5A6B5B6 magic
  ##   30     : key class (0x10 = key pair)
  ##   31     : reserved key index (0x00)
  result[0] = 0x10'u8

  result[18] = uint8((objectId shr 24) and 0xFF'u32)
  result[19] = uint8((objectId shr 16) and 0xFF'u32)
  result[20] = uint8((objectId shr 8) and 0xFF'u32)
  result[21] = uint8(objectId and 0xFF'u32)

  for i, b in NxpEcReferenceMagic.pairs:
    result[22 + i] = b

  result[30] = NxpEcReferenceKeyPairClass
  result[31] = NxpEcReferenceKeyIndex

proc appendPemBody(result: var string, base64Text: string) =
  const PemLineLength = 64

  var offset = 0
  while offset < base64Text.len:
    let lineEnd = min(offset + PemLineLength, base64Text.len)
    result.add(base64Text[offset ..< lineEnd])
    result.add('\n')
    offset = lineEnd

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
  validateP256PublicKey(publicKey)

  let referenceValue = p256ReferencePrivateValue(objectId)

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
  let der = encodeP256ReferenceKeyDer(objectId, publicKey)
  let base64Text = encodeBase64(der)

  result = "-----BEGIN EC PRIVATE KEY-----\n"
  result.appendPemBody(base64Text)
  result.add("-----END EC PRIVATE KEY-----\n")
