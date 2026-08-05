# NXP OpenSSL Provider integration

## Purpose

This document defines the boundary between `se050_nim` / `se050ctl`, OpenSSL 3, the NXP `se05x-openssl-provider`, and ordinary OpenSSL-backed applications.

Two key-reference forms are intentionally supported:

1. `nxp:0x...` URI for explicit Provider diagnostics/tooling
2. NXP Reference Key PEM for transparent use through normal `keyFile` / `-key` filename APIs

Both P-256 and P-384 have been hardware-tested through Reference Key decoding, Provider-backed SE050 ECDSA signing, and ordinary Nim `std/net` TLS 1.2/TLS 1.3 mutual TLS.

## Provider build/runtime

Use NXP's official `se05x-openssl-provider`. `se050_nim` itself does not depend on Plug & Trust middleware; the Provider is only the OpenSSL runtime boundary.

Build `libsssProvider.so` for the target architecture. When OpenSSL dynamically loads the Provider, the Provider itself must resolve `libcrypto.so.3`.

```sh
readelf -d /usr/local/lib/libsssProvider.so | grep NEEDED
ldd /usr/local/lib/libsssProvider.so
```

If the target build lacks its `libcrypto.so.3` dependency, link the Provider target explicitly against `crypto`.

## I2C connection

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

The current threat model treats the host OS as trusted and uses a Plain direct-I2C session. The main boundary is private-key non-exportability, not prevention of SE050 use after host compromise.

## 1. Provider-native Object URI

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
# nxp:0x30000200
```

The URI is useful when a command intentionally addresses the NXP Provider.

```sh
openssl pkeyutl \
  --provider /usr/local/lib/libsssProvider.so \
  --provider default \
  -inkey nxp:0x30000200 \
  -sign -rawin \
  -in input.txt \
  -out signature.der \
  -digest sha256
```

The URI does not encode curve or provisioning origin, so validate the managed TLS object separately before relying on it.

## 2. Reference Key PEM

Reference Key PEM is the standard path for transparent applications.

The NXP EC Reference Key uses a SEC1 `EC PRIVATE KEY` structure. Its privateKey OCTET STRING contains an SE050 Object reference rather than the real scalar; the public point and named-curve metadata remain ordinary EC key data.

`se050_nim` supports:

- P-256: 32-byte reference field + `prime256v1`
- P-384: 48-byte reference field + `secp384r1`

No real private scalar is stored in the Reference Key.

Internally generated P-256:

```sh
se050ctl tls-key-ref-file \
  -b 0 --profile test --identity 0 --slot A \
  --out device.key
```

Imported P-384:

```sh
se050ctl tls-key-ref-file \
  -b 0 --profile test --identity 0 --slot B \
  --curve p384 --imported \
  --out device.key
```

Export first validates the live object type, persistence, policy, attestation certificate/signature, origin, and public-key equality. The output is installed with mode 0600 and existing paths are never overwritten.

## 3. Provider autoload

```ini
config_diagnostics = 1
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
nxp_prov = nxp_sect
default = default_sect

[nxp_sect]
identity = nxp_prov
module = /usr/local/lib/libsssProvider.so
activate = 1

[default_sect]
activate = 1
```

```sh
export OPENSSL_CONF=/path/to/openssl.cnf
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

The OpenSSL command can then consume the Reference Key like an ordinary filename.

```sh
openssl pkeyutl \
  -inkey device.key \
  -sign -rawin \
  -in input.txt \
  -out signature.der \
  -digest sha384
```

## 4. External private-key import

```sh
se050ctl tls-key-import \
  -b 0 \
  --profile test --identity 0 --slot B \
  --curve p384 \
  --key client.key \
  --cert client.crt
```

Unencrypted PEM and DER EC private keys are accepted. The sequence is:

```text
decode and validate the private key
-> verify matching X.509 certificate public key
-> for P-384, require the curve to be instantiated
-> require an empty managed slot
-> sensitive WriteECKey
-> imported-origin attestation validation
-> source/live public-key equality
```

Existing slots are never overwritten. Private-key and temporary APDU buffers are cleared, and raw sensitive transport frames are redacted even in debug mode.

## 5. P-384 curve state

`ReadECCurveList` reports current Weierstrass curve instantiation, not silicon capability.

```sh
se050ctl curve-list -b 0
se050ctl curve-provision-p384 -b 0 --yes
```

P-384 provisioning writes the fixed standard secp384r1 domain parameters into persistent global SE05x curve state. It is idempotent when already instantiated and performs best-effort rollback after a confirmed create if later setup/verification fails.

## 6. Ordinary Nim `std/net`

`tools/std_net_mtls_client.nim` contains no SE050 or Provider-specific API calls. It simply supplies certificate, key, and CA filenames to `newContext()`.

```nim
let ctx = newContext(
  verifyMode = CVerifyPeer,
  certFile = certFile,
  keyFile = keyFile,
  caFile = caFile
)
```

With the Provider autoloaded from `openssl.cnf` and a Reference Key used as `keyFile`, P-256 and P-384 both pass TLS 1.3 and TLS 1.2 mutual TLS.

## 7. Integration tests

```text
tools/se050_reference_key_provider_test.sh
tools/se050_reference_key_autoload_test.sh
tools/se050_external_key_import_test.sh
tools/se050_external_p384_key_import_test.sh
tools/se050_std_net_mtls_test.sh
tools/se050_external_key_std_net_mtls_test.sh
tools/std_net_mtls_client.nim
```

`se050_external_key_std_net_mtls_test.sh --curve p256|p384` performs disposable software-key creation, safe import into a proven-empty test slot, Reference Key export, ordinary Nim `std/net` TLS 1.3/TLS 1.2, and safe cleanup.

See [`local-mtls-test.md`](local-mtls-test.md).
