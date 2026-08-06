import std/unittest

import se050_nim

suite "SE050 direct I2C endpoint resolution":
  test "uses direct I2C environment endpoint":
    let endpoint = resolveSe050I2cEndpointWithPort(
      "",
      "",
      "/dev/i2c-0:0x48"
    )

    check endpoint.bus == 0
    check endpoint.address == 0x48'u8

  test "uses default address when environment endpoint omits it":
    let endpoint = resolveSe050I2cEndpointWithPort(
      "",
      "",
      "/dev/i2c-12"
    )

    check endpoint.bus == 12
    check endpoint.address == DefaultSe050I2cAddress

  test "CLI values override environment values":
    let endpoint = resolveSe050I2cEndpointWithPort(
      "3",
      "0x49",
      "/dev/i2c-0:0x48"
    )

    check endpoint.bus == 3
    check endpoint.address == 0x49'u8

  test "CLI bus does not inherit environment address":
    let endpoint = resolveSe050I2cEndpointWithPort(
      "3",
      "",
      "/dev/i2c-0:0x49"
    )

    check endpoint.bus == 3
    check endpoint.address == DefaultSe050I2cAddress

  test "CLI bus can override non-I2C provider endpoint":
    let endpoint = resolveSe050I2cEndpointWithPort(
      "3",
      "",
      "127.0.0.1:8040"
    )

    check endpoint.bus == 3
    check endpoint.address == DefaultSe050I2cAddress

  test "CLI address can use environment bus":
    let endpoint = resolveSe050I2cEndpointWithPort(
      "",
      "0x49",
      "/dev/i2c-7:0x48"
    )

    check endpoint.bus == 7
    check endpoint.address == 0x49'u8

  test "requires an explicit or environment bus":
    expect ValueError:
      discard resolveSe050I2cEndpointWithPort("", "", "")

  test "rejects AccessManager endpoint":
    expect ValueError:
      discard resolveSe050I2cEndpointWithPort(
        "",
        "",
        "127.0.0.1:8040"
      )

  test "rejects malformed direct I2C endpoint":
    expect ValueError:
      discard resolveSe050I2cEndpointWithPort(
        "",
        "",
        "/dev/i2c-0:"
      )

  test "rejects out-of-range I2C address":
    expect ValueError:
      discard resolveSe050I2cEndpointWithPort(
        "",
        "",
        "/dev/i2c-0:0x80"
      )
