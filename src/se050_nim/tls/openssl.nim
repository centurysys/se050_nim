# =============================================================================
# SE050 TLS identity OpenSSL Provider references
# =============================================================================
#
# NXP se05x-openssl-provider can reference an existing Secure Object directly
# with the OSSL_STORE URI form "nxp:0x12345678". This module keeps that
# provider-specific representation separate from TLS identity Object-ID layout
# and cloud-specific provisioning.

import std/strformat
import std/strutils

import ../keys
import ./profile

const
  NxpOpenSslProviderUriPrefix* = "nxp:"


const
  # SubjectPublicKeyInfo prefix for an uncompressed NIST P-256 point:
  #   SEQUENCE {
  #     AlgorithmIdentifier { id-ecPublicKey, prime256v1 },
  #     BIT STRING <0x04 || X || Y>
  #   }
  P256SubjectPublicKeyInfoPrefix* = [
    0x30'u8, 0x59'u8,
    0x30'u8, 0x13'u8,
    0x06'u8, 0x07'u8, 0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8,
    0x3D'u8, 0x02'u8, 0x01'u8,
    0x06'u8, 0x08'u8, 0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8,
    0x3D'u8, 0x03'u8, 0x01'u8, 0x07'u8,
    0x03'u8, 0x42'u8, 0x00'u8
  ]

  # SubjectPublicKeyInfo prefix for an uncompressed NIST P-384 point:
  #   SEQUENCE {
  #     AlgorithmIdentifier { id-ecPublicKey, secp384r1 },
  #     BIT STRING <0x04 || X || Y>
  #   }
  P384SubjectPublicKeyInfoPrefix* = [
    0x30'u8, 0x76'u8,
    0x30'u8, 0x10'u8,
    0x06'u8, 0x07'u8, 0x2A'u8, 0x86'u8, 0x48'u8, 0xCE'u8,
    0x3D'u8, 0x02'u8, 0x01'u8,
    0x06'u8, 0x05'u8, 0x2B'u8, 0x81'u8, 0x04'u8, 0x00'u8, 0x22'u8,
    0x03'u8, 0x62'u8, 0x00'u8
  ]

proc p256PublicKeyToSpkiDer*(publicKey: openArray[uint8]): seq[uint8] =
  ## Wraps a raw uncompressed P-256 point in X.509 SubjectPublicKeyInfo DER.
  ##
  ## SE050 ReadObject returns 0x04 || X || Y for NIST P-256 public keys.
  ## CSR public keys are exposed by OpenSSL as SubjectPublicKeyInfo, so this
  ## conversion gives callers a byte-for-byte comparison format without
  ## involving a private key or provider-specific reference structure.
  if publicKey.len != 65 or publicKey[0] != 0x04'u8:
    raise newException(
      ValueError,
      "public key is not a 65-byte uncompressed NIST P-256 point"
    )

  result = @[]
  for b in P256SubjectPublicKeyInfoPrefix:
    result.add(b)
  for b in publicKey:
    result.add(b)

proc p384PublicKeyToSpkiDer*(publicKey: openArray[uint8]): seq[uint8] =
  ## Wraps a raw uncompressed P-384 point in X.509 SubjectPublicKeyInfo DER.
  if publicKey.len != 97 or publicKey[0] != 0x04'u8:
    raise newException(
      ValueError,
      "public key is not a 97-byte uncompressed NIST P-384 point"
    )

  result = @[]
  for b in P384SubjectPublicKeyInfoPrefix:
    result.add(b)
  for b in publicKey:
    result.add(b)

proc ecPublicKeyToSpkiDer*(
    curve: EcCurveKind,
    publicKey: openArray[uint8]
): seq[uint8] =
  ## Converts one supported managed TLS EC public point to SPKI DER.
  case curve
  of ecCurveP256:
    result = p256PublicKeyToSpkiDer(publicKey)
  of ecCurveP384:
    result = p384PublicKeyToSpkiDer(publicKey)
  else:
    raise newException(
      ValueError,
      &"SPKI conversion does not support curve {curveName(curve)}"
    )

proc opensslProviderKeyUri*(objectId: uint32): string =
  ## Returns the NXP OpenSSL Provider URI for an existing SE05x key object.
  result = &"{NxpOpenSslProviderUriPrefix}0x{objectId.toHex(8)}"

proc opensslProviderKeyUri*(profile: TlsIdentityProfile): string =
  ## Returns the NXP OpenSSL Provider URI for one validated TLS identity slot.
  if not profile.isValid():
    raise newException(ValueError, "TLS identity profile is invalid")
  result = opensslProviderKeyUri(profile.keyObjectId)
