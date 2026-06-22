# =============================================================================
# SE050 APDU helpers
# =============================================================================
#
# Common helpers for APDU responses returned by Se050Transport.transceiveApdu().
#
# This module intentionally knows only about APDU-level status words and the
# SE050 IoT applet SELECT command. It does not know about UID/object/key
# semantics.

import ./errors
import ./transport

# =============================================================================
# Constants
# =============================================================================

const
  SwSuccess* = 0x9000'u16

  SelectAppletApdu*: array[22, uint8] = [
    0x00'u8, 0xA4'u8, 0x04'u8, 0x00'u8, 0x10'u8,
    0xA0'u8, 0x00'u8, 0x00'u8, 0x03'u8,
    0x96'u8, 0x54'u8, 0x53'u8, 0x00'u8,
    0x00'u8, 0x00'u8, 0x01'u8, 0x03'u8,
    0x00'u8, 0x00'u8, 0x00'u8, 0x00'u8,
    0x00'u8
  ]

# =============================================================================
# APDU response helpers
# =============================================================================

proc statusWord*(response: openArray[uint8]): SE[uint16] =
  ## Returns the APDU status word from a response ending with SW1 SW2.
  if response.len < 2:
    return fail[uint16](seInvalidResponse, "APDU response is too short")

  let sw1 = uint16(response[response.len - 2])
  let sw2 = uint16(response[response.len - 1])
  result = ok((sw1 shl 8) or sw2)

proc checkStatus*(response: openArray[uint8], context: string): SE[void] =
  ## Checks that the APDU response status word is 0x9000.
  let sw = statusWord(response)
  if not sw.ok:
    return fail[void](sw.error.kind, sw.error.message, sw.error.sw)

  if sw.value != SwSuccess:
    return fail[void](
      seApduStatusError,
      context & " failed",
      sw.value
    )

  result = ok()

proc dataWithoutStatus*(response: openArray[uint8]): SE[seq[uint8]] =
  ## Returns response data without the trailing SW1 SW2 bytes.
  if response.len < 2:
    return fail[seq[uint8]](seInvalidResponse, "APDU response is too short")

  result = ok(@response[0 ..< response.len - 2])

# =============================================================================
# Applet selection
# =============================================================================

proc selectApplet*(se: Se050Transport): SE[void] =
  ## Selects the SE050 IoT applet.
  let response = se.transceiveApdu(SelectAppletApdu)
  if not response.ok:
    return fail[void](response.error.kind, response.error.message, response.error.sw)

  result = checkStatus(response.value, "SELECT applet")
