# =============================================================================
# SE050 attestation constants
# =============================================================================
#
# Constants shared by generic ReadObject-with-Attestation users. These values
# describe the pre-provisioned attestation identity and Applet 7.2 request
# encoding, and therefore do not belong to the kitting-specific profile.

const
  # NXP pre-provisioned die-individual ECC attestation objects.
  Se050AttestationKeyObjectId* = 0xF0000012'u32
  Se050AttestationCertificateObjectId* = 0xF0000013'u32

  Se050AttestationAlgorithmEcSha256* = 0x21'u8
  Se050AttestationFreshnessMaxLength* = 16
