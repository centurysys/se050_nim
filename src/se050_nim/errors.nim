# =============================================================================
# SE050 error and result types
# =============================================================================

import std/strutils

type
  Se050ErrorKind* = enum
    seOk,

    # API / caller errors
    seInvalidArgument,

    # I2C / transport errors
    seI2cWriteFailed,
    seI2cReadFailed,
    seFrameTooShort,
    seFrameTooLong,
    seInvalidCrc,
    seInvalidNad,
    seInvalidLen,
    seUnexpectedFrame,
    seDeviceRnaK,
    seTooManyRetries,

    # APDU / SE050 logical errors
    seApduTooLarge,
    seApduStatusError,
    seInvalidResponse,
    seUidNotFound

  Se050Error* = object
    kind*: Se050ErrorKind
    message*: string
    sw*: uint16

  SE*[T] = object
    ## SE050 result type.
    ##
    ## This project uses explicit Result-style returns instead of exceptions.
    ok*: bool
    when T is void:
      discard
    else:
      value*: T
    error*: Se050Error

# =============================================================================
# Constructors
# =============================================================================

proc ok*(): SE[void] =
  result.ok = true

proc ok*[T](value: T): SE[T] =
  result.ok = true
  result.value = value

proc fail*[T](
    kind: Se050ErrorKind,
    message: string,
    sw: uint16 = 0
): SE[T] =
  result.ok = false
  result.error = Se050Error(
    kind: kind,
    message: message,
    sw: sw
  )

# =============================================================================
# Helpers
# =============================================================================

proc isOk*[T](r: SE[T]): bool =
  result = r.ok

proc isErr*[T](r: SE[T]): bool =
  result = not r.ok

proc errorMessage*(e: Se050Error): string =
  if e.sw != 0:
    result = e.message & " SW=0x" & e.sw.toHex(4)
  else:
    result = e.message
