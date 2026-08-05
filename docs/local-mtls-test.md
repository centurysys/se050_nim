# Local SE050 TLS identity mTLS tests

## Purpose

Before adding cloud-specific behavior, verify that an SE050 TLS client private key can be used through the NXP OpenSSL Provider by an **ordinary OpenSSL-backed application**.

The final application-level target is `tools/std_net_mtls_client.nim`. It contains no SE050 or NXP Provider API calls and uses only normal Nim `std/net` `certFile`, `keyFile`, and `caFile` paths.

## Verified matrix

| TLS identity | Provisioning | TLS 1.3 | TLS 1.2 |
|---|---|:---:|:---:|
| P-256 | SE050 internal generation | OK | OK |
| P-256 | external import | OK | OK |
| P-384 | external import | OK | OK |

Managed internal generation is currently P-256 only; `tls-keygen` does not generate P-384.

## Requirements

- OpenSSL 3.x
- target-architecture NXP `libsssProvider.so`
- `se050ctl`
- working `EX_SSS_BOOT_SSS_PORT`
- `std_net_mtls_client` built with `nim c -d:ssl`

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

## What “ordinary application” means

The client is conceptually just:

```nim
let ctx = newContext(
  verifyMode = CVerifyPeer,
  certFile = certFile,
  keyFile = keyFile,
  caFile = caFile
)
```

The `keyFile` is an NXP Reference Key PEM and the Provider is autoloaded by `OPENSSL_CONF`. The application does not know the SE050 Object ID, Provider URI, or I2C settings.

## Existing-identity transparent test

`tools/se050_std_net_mtls_test.sh` never creates or deletes an SE050 key. It validates the requested identity, exports a Reference Key, creates temporary test PKI material, and runs both TLS 1.3 and TLS 1.2.

Internally generated P-256:

```sh
./tools/se050_std_net_mtls_test.sh \
  --se050ctl ./bin/se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --profile test --identity 0 --slot A \
  --curve p256 \
  --client ./tools/std_net_mtls_client
```

Imported P-384:

```sh
./tools/se050_std_net_mtls_test.sh \
  --se050ctl ./bin/se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --profile test --identity 0 --slot B \
  --curve p384 --imported \
  --client ./tools/std_net_mtls_client
```

The test validates origin semantics, exports a 0600 Reference Key, exports live SPKI DER, autoloads NXP/default Providers, creates a client CSR/certificate, checks certificate/live-public-key byte equality, and runs TLS 1.3 and TLS 1.2 through the plain Nim client.

For the TLS 1.2 diagnostic server constraints, P-256 uses ECDSA/SHA-256 with `prime256v1`; P-384 uses ECDSA/SHA-384 with `secp384r1`.

## Disposable external-import test

`tools/se050_external_key_std_net_mtls_test.sh` covers external import through transparent TLS using only a test slot proven empty at start.

```sh
./tools/se050_external_key_std_net_mtls_test.sh \
  --se050ctl ./bin/se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --curve p384 \
  --identity 0 --slot B \
  --bus 0 --address 0x48 \
  --client ./tools/std_net_mtls_client
```

For P-384 it verifies that the curve is already instantiated and never changes global curve state itself. Existing objects are never overwritten or deleted. Cleanup is limited to the object created in a slot proven empty at startup.

## Lower-level Provider diagnostics

```text
tools/se050_reference_key_provider_test.sh
tools/se050_reference_key_autoload_test.sh
tools/se050_external_key_import_test.sh
tools/se050_external_p384_key_import_test.sh
tools/se050_local_mtls_test.sh
```

These isolate Provider URI, Reference Key decoding, explicit/autoload Provider configuration, OpenSSL CLI signing, and OpenSSL CLI mTLS. The final transparent application test is `se050_std_net_mtls_test.sh`.

## Security boundary

- real SE050 private scalars are never exported to the filesystem
- Reference Key files contain only Object-reference/provider metadata, public key, and curve metadata
- external private-key input buffers are cleared after import
- raw sensitive WriteECKey transport frames are redacted in debug output
- the host OS is trusted and direct I2C uses a Plain session
- SCP03, host authentication, multi-process SE050 arbitration, and cloud policy are outside this test
