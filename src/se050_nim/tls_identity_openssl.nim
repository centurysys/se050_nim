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

import ./tls_identity_profile

const
  NxpOpenSslProviderUriPrefix* = "nxp:"

proc opensslProviderKeyUri*(objectId: uint32): string =
  ## Returns the NXP OpenSSL Provider URI for an existing SE05x key object.
  result = &"{NxpOpenSslProviderUriPrefix}0x{objectId.toHex(8)}"

proc opensslProviderKeyUri*(profile: TlsIdentityProfile): string =
  ## Returns the NXP OpenSSL Provider URI for one validated TLS identity slot.
  if not profile.isValid():
    raise newException(ValueError, "TLS identity profile is invalid")
  result = opensslProviderKeyUri(profile.keyObjectId)
