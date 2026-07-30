import std/options
import std/strutils
import std/unittest

import se050_nim

suite "production kitting Object ID guard":
  test "reserves only the fixed production firmware KEX Object ID":
    check KittingProductionFirmwareKexObjectId.isProductionKittingObjectId()
    check not KittingTestFirmwareKexObjectId.isProductionKittingObjectId()
    check not 0x200000FF'u32.isProductionKittingObjectId()
    check not 0x20000101'u32.isProductionKittingObjectId()

  test "rejects every generic mutation of the production Object ID":
    let testCases: array[4, tuple[
      mutation: KittingObjectMutationKind,
      prefix: string
    ]] = [
      (mutation: komCreate, prefix: "create refused:"),
      (mutation: komGenerate, prefix: "keygen refused:"),
      (mutation: komWrite, prefix: "write refused:"),
      (mutation: komDelete, prefix: "delete refused:")
    ]

    for testCase in testCases:
      let guard = productionKittingMutationError(
        KittingProductionFirmwareKexObjectId,
        testCase.mutation
      )

      require guard.isSome
      check guard.get().startsWith(testCase.prefix)
      check guard.get().contains("0x20000100")
      check guard.get().contains("reserved for the production firmware KEX key")

  test "does not reject mutations of the disposable test Object ID":
    for mutation in KittingObjectMutationKind:
      check productionKittingMutationError(
        KittingTestFirmwareKexObjectId,
        mutation
      ).isNone

  test "does not reserve adjacent customer Object IDs":
    for objectId in [0x200000FF'u32, 0x20000101'u32]:
      for mutation in KittingObjectMutationKind:
        check productionKittingMutationError(objectId, mutation).isNone
