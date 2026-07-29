# =============================================================================
# Embedded NXP attestation trust store
# =============================================================================
#
# The NXP Attestation ECC root and intermediate certificates are compiled into
# the binaries with staticRead(). Kitting verification must not accept a caller-
# supplied replacement trust anchor.

import std/os

const
  TrustStoreCertificateDir = parentDir(currentSourcePath()) / "certs"

  NxpAttestationRootDerRaw = staticRead(
    TrustStoreCertificateDir / "nxp-attestation-ecc-root.der"
  )

  NxpAttestationIntermediateDerRaw = staticRead(
    TrustStoreCertificateDir / "nxp-attestation-ecc-intermediate.der"
  )

proc rawStringToBytes(data: string): seq[uint8] =
  result = newSeq[uint8](data.len)
  for index, value in data:
    result[index] = uint8(ord(value))

proc nxpAttestationRootDer*(): seq[uint8] =
  ## Returns a copy of the embedded NXP Attestation ECC root certificate.
  result = rawStringToBytes(NxpAttestationRootDerRaw)

proc nxpAttestationIntermediateDer*(): seq[uint8] =
  ## Returns a copy of the embedded NXP Attestation ECC intermediate certificate.
  result = rawStringToBytes(NxpAttestationIntermediateDerRaw)

proc nxpAttestationTrustAnchors*(): seq[seq[uint8]] =
  ## Returns the fixed trust anchors accepted by kitting verification.
  result = @[nxpAttestationRootDer()]

proc nxpAttestationIntermediates*(): seq[seq[uint8]] =
  ## Returns the fixed intermediate certificates used to build the device chain.
  result = @[nxpAttestationIntermediateDer()]
