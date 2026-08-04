# =============================================================================
# Board identity helpers
# =============================================================================

import ../errors
import ./profile

proc parseBoardSerialNumber*(raw: string): SE[string] =
  ## Parses the Device Tree serial-number property.
  ## Only trailing NUL/CR/LF bytes are removed. Leading zeroes are preserved.
  var endIndex = raw.len
  while endIndex > 0 and raw[endIndex - 1] in {'\0', '\r', '\n'}:
    dec endIndex

  if endIndex == 0:
    return fail[string](
      seInvalidResponse,
      "board serial number is empty"
    )

  let serialNumber = raw[0 ..< endIndex]
  for c in serialNumber:
    if c < '0' or c > '9':
      return fail[string](
        seInvalidResponse,
        "board serial number must contain ASCII digits only"
      )

  result = ok(serialNumber)

proc readBoardSerialNumber*(
    path: string = BoardSerialNumberPath
): SE[string] =
  ## Reads and validates the board serial number from Device Tree.
  try:
    result = parseBoardSerialNumber(readFile(path))
  except CatchableError as e:
    result = fail[string](
      seInvalidResponse,
      "failed to read board serial number from " & path & ": " & e.msg
    )
