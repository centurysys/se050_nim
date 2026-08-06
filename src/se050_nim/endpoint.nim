# =============================================================================
# SE050 direct-I2C endpoint resolution
# =============================================================================
#
# NXP tools and the se05x OpenSSL Provider commonly use
# EX_SSS_BOOT_SSS_PORT=/dev/i2c-N[:0xADDR].  se050_nim talks directly to the
# device over T=1/I2C, so only that direct-I2C form is accepted here.

import std/options
import std/os
import std/strformat
import std/strutils

import ./transport

const
  ExSssBootSssPortEnv* = "EX_SSS_BOOT_SSS_PORT"
  DirectI2cPrefix = "/dev/i2c-"

type
  Se050I2cEndpoint* = object
    bus*: int
    address*: uint8

  DirectI2cEndpointSpec = object
    bus: int
    address: Option[uint8]

proc parseBusNumber(value: string): int =
  let text = value.strip()
  if text.len == 0:
    raise newException(ValueError, "I2C bus number is empty")

  result = parseInt(text)
  if result < 0:
    raise newException(ValueError, &"I2C bus number must be >= 0: {value}")

proc parseI2cAddress(value: string): uint8 =
  ## Parse a 7-bit I2C address as hexadecimal.
  ##
  ## Both "48" and "0x48" mean address 0x48, matching the existing CLI
  ## behavior.
  var text = value.strip()
  if text.startsWith("0x") or text.startsWith("0X"):
    text = text[2 .. ^1]

  if text.len == 0:
    raise newException(ValueError, "I2C address is empty")

  let parsed = parseHexInt(text)
  if parsed < 0 or parsed > 0x7F:
    raise newException(ValueError, &"I2C address must be in 7-bit range: {value}")

  result = uint8(parsed)

proc parseDirectI2cEndpoint(value: string): DirectI2cEndpointSpec =
  let text = value.strip()
  if not text.startsWith(DirectI2cPrefix):
    raise newException(
      ValueError,
      &"{ExSssBootSssPortEnv} must be a direct I2C endpoint such as /dev/i2c-0:0x48: {value}"
    )

  if text.len == DirectI2cPrefix.len:
    raise newException(
      ValueError,
      &"{ExSssBootSssPortEnv} has no I2C bus number: {value}"
    )

  let suffix = text[DirectI2cPrefix.len .. ^1]
  let separator = suffix.find(':')
  if separator < 0:
    result.bus = parseBusNumber(suffix)
    result.address = none(uint8)
    return

  if suffix.count(':') != 1:
    raise newException(
      ValueError,
      &"{ExSssBootSssPortEnv} is not a direct I2C endpoint: {value}"
    )

  let busText = suffix[0 ..< separator]
  let addressText = suffix[separator + 1 .. ^1]
  result.bus = parseBusNumber(busText)
  result.address = some(parseI2cAddress(addressText))

proc resolveSe050I2cEndpointWithPort*(
    busText: string,
    addressText: string,
    environmentPort: string
): Se050I2cEndpoint =
  ## Resolve one direct SE050 I2C endpoint.
  ##
  ## An explicit CLI bus selects a complete direct-I2C endpoint and therefore
  ## does not inherit an address from EX_SSS_BOOT_SSS_PORT.  This avoids
  ## accidentally combining a bus from one endpoint with an address belonging
  ## to another.
  ##
  ## Resolution order:
  ##
  ##   bus:     CLI > EX_SSS_BOOT_SSS_PORT
  ##   address: CLI > selected environment endpoint > 0x48
  ##
  ## There is intentionally no default bus number.  Without a CLI bus or a
  ## direct-I2C environment endpoint, resolution fails instead of silently
  ## selecting /dev/i2c-0.
  if busText.strip().len > 0:
    result.bus = parseBusNumber(busText)
    if addressText.strip().len > 0:
      result.address = parseI2cAddress(addressText)
    else:
      result.address = transport.DefaultSe050I2cAddress
    return

  if environmentPort.strip().len == 0:
    raise newException(
      ValueError,
      &"I2C bus is not specified; use -b/--bus or set {ExSssBootSssPortEnv}=/dev/i2c-N[:0xADDR]"
    )

  let environment = parseDirectI2cEndpoint(environmentPort)
  result.bus = environment.bus

  if addressText.strip().len > 0:
    result.address = parseI2cAddress(addressText)
  elif environment.address.isSome:
    result.address = environment.address.get()
  else:
    result.address = transport.DefaultSe050I2cAddress

proc resolveSe050I2cEndpoint*(
    busText: string,
    addressText: string
): Se050I2cEndpoint =
  ## Resolve CLI endpoint text using EX_SSS_BOOT_SSS_PORT when present.
  result = resolveSe050I2cEndpointWithPort(
    busText,
    addressText,
    getEnv(ExSssBootSssPortEnv)
  )
