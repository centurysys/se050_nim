# Package

version       = "0.1.0"
author        = "Takeyoshi Kikuchi"
description   = "Minimal Nim library and CLI for NXP SE050 using T=1 over I2C (no middleware dependency)"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
bin           = @["se050ctl", "se050_kitting_export"]
namedBin["se050_kitting_export"] = "se050-kitting-export"
installExt    = @["nim"]


# Dependencies

requires "nim >= 2.2.10"
requires "results >= 0.5.1"
requires "argparse >= 4.0.2"
