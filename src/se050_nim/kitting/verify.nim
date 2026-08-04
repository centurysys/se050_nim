# =============================================================================
# Offline SE050 kitting record verification
# =============================================================================
#
# Combines the structural CSV checks, NXP certificate-chain verification,
# Applet 7.2 attestation signature verification, and signed Secure Object
# semantic validation into one reusable API.
#
# This module does not access I2C. Factory exporters, local verification tools,
# and future database importers can therefore share the same trust decision.

import ../errors
import ../x509_verify
import ../attestation/read
import ../attestation/signature_verify
import ./profile
import ./record
import ./csv
import ./attestation_verify

# =============================================================================
# Types
# =============================================================================

type
  VerifiedKittingRecord* = object
    ## A kitting record accepted by every offline verification layer.
    record*: KittingRecord
    attested*: AttestedObjectRead
    certificateChain*: CertificateChainVerification
    signature*: AttestationSignatureVerification
    semantics*: KittingAttestationSemantics

# =============================================================================
# Internal helpers
# =============================================================================

proc verificationFailure[T](
    prefix: string,
    source: Se050Error
): SE[T] =
  result = fail[T](
    source.kind,
    prefix & source.message,
    source.sw
  )

# =============================================================================
# Public API
# =============================================================================

proc verifyKittingRecord*(
    record: KittingRecord,
    trustAnchorsDer: openArray[seq[uint8]],
    intermediatesDer: openArray[seq[uint8]]
): SE[VerifiedKittingRecord] =
  ## Performs every offline check required before a public key is trusted.
  ##
  ## Verification order:
  ##   1. Restore metadata-bound freshness and the captured attestation.
  ##   2. Validate the device certificate chain to explicit trust anchors.
  ##   3. Verify the Applet 7.2 ECDSA attestation signature.
  ##   4. Validate the signed object ID, type, origin, policy, and key size.
  let attested = restoreKittingAttestation(record)
  if not attested.ok:
    return verificationFailure[VerifiedKittingRecord](
      "kitting record structure: ",
      attested.error
    )

  let chain = verifyCertificateChain(
    leafCertificateDer = record.attestationCertificate,
    trustAnchorsDer = trustAnchorsDer,
    intermediatesDer = intermediatesDer
  )
  if not chain.ok:
    return verificationFailure[VerifiedKittingRecord](
      "kitting certificate chain: ",
      chain.error
    )

  let signature = verifyAttestationSignature(
    attested = attested.value,
    certificateDer = record.attestationCertificate
  )
  if not signature.ok:
    return verificationFailure[VerifiedKittingRecord](
      "kitting attestation signature: ",
      signature.error
    )

  let semantics = verifyKittingAttestationSemantics(
    attested = attested.value,
    profile = record.profile()
  )
  if not semantics.ok:
    return verificationFailure[VerifiedKittingRecord](
      "kitting attestation semantics: ",
      semantics.error
    )

  result = ok(VerifiedKittingRecord(
    record: record,
    attested: attested.value,
    certificateChain: chain.value,
    signature: signature.value,
    semantics: semantics.value
  ))

proc verifyKittingRecord*(
    record: KittingRecord,
    trustAnchorsDer: openArray[seq[uint8]]
): SE[VerifiedKittingRecord] =
  ## Convenience overload for a certificate chain without intermediates.
  let noIntermediates: seq[seq[uint8]] = @[]
  result = verifyKittingRecord(record, trustAnchorsDer, noIntermediates)

proc verifyKittingCsvRecord*(
    csvText: string,
    serialNumber: string,
    profileKind: KittingProfileKind,
    trustAnchorsDer: openArray[seq[uint8]],
    intermediatesDer: openArray[seq[uint8]],
    keyRole: string = KittingKeyRoleFirmwareKex
): SE[VerifiedKittingRecord] =
  ## Selects exactly one device record from a multi-device CSV and verifies it.
  let records = decodeKittingCsv(csvText)
  if not records.ok:
    return verificationFailure[VerifiedKittingRecord](
      "kitting CSV: ",
      records.error
    )

  let record = findKittingRecord(
    records = records.value,
    serialNumber = serialNumber,
    profileKind = profileKind,
    keyRole = keyRole
  )
  if not record.ok:
    return verificationFailure[VerifiedKittingRecord](
      "kitting CSV selection: ",
      record.error
    )

  result = verifyKittingRecord(
    record = record.value,
    trustAnchorsDer = trustAnchorsDer,
    intermediatesDer = intermediatesDer
  )

proc verifyKittingCsvRecord*(
    csvText: string,
    serialNumber: string,
    profileKind: KittingProfileKind,
    trustAnchorsDer: openArray[seq[uint8]],
    keyRole: string = KittingKeyRoleFirmwareKex
): SE[VerifiedKittingRecord] =
  ## Convenience overload for a certificate chain without intermediates.
  let noIntermediates: seq[seq[uint8]] = @[]
  result = verifyKittingCsvRecord(
    csvText,
    serialNumber,
    profileKind,
    trustAnchorsDer,
    noIntermediates,
    keyRole
  )
