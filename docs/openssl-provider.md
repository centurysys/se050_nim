# NXP OpenSSL Provider integration

## Purpose

Define the boundary for using TLS client identity keys provisioned and validated by `se050_nim` / `se050ctl` from OpenSSL 3 through NXP's official `se05x-openssl-provider`.

Cloud-specific enrollment is intentionally excluded. First verify that the provider can reference an existing SE050 object and perform ECDSA signing; CSR and local mTLS follow in later steps.

## Provider

Official NXP repository:

```text
https://github.com/NXPPlugNTrust/se05x-openssl-provider
```

The current provider supports OpenSSL 3.x and documents EC key generation, EC sign/verify, ECDH, CSR, and TLS 1.2/1.3 client use.

Existing SE050 keys can be referenced directly using:

```text
nxp:0x12345678
```

Therefore `se050_nim` does not generate NXP reference-key PEM files itself. The Object-ID URI is the initial standard path.

## se050ctl mapping

Example:

```sh
se050ctl tls-key-ref --profile test --identity 0 --slot A
```

Output:

```text
nxp:0x30000200
```

Applications should not duplicate the Object-ID calculation; the TLS identity profile remains the source of truth.

## Native provider build

The upstream README uses:

```sh
git clone --recurse-submodules https://github.com/NXPPlugNTrust/se05x-openssl-provider.git
cd se05x-openssl-provider
mkdir build
cd build
cmake ../
cmake -DPTMW_HostCrypto=OPENSSL .
cmake --build .
```

The build also copies `libsssProvider.so` into the repository `bin` directory. `cmake --install .` installs the shared library using the configured install prefix.

For product-rootfs cross builds, add the appropriate CMake toolchain file and sysroot. Both the provider and its `simw_lib` submodule must be built for the target architecture.

## I2C connection

Current NXP support guidance allows the Linux I2C port to be selected with `EX_SSS_BOOT_SSS_PORT`.

Example:

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
```

Adjust the bus/address for the target hardware.

This project treats the Host OS as a trusted environment and uses TLS private-key non-exportability as the primary security boundary. Therefore the direct-I2C plain session is intentional. Provider warnings such as `Communication channel is Plain` / `Not recommended for production use` are expected for this design. Preventing SE050 misuse after Host OS compromise is out of scope, so SCP03, Access Manager, and host-authentication credentials are not introduced.

## Step 5 hardware check

### 1. Validate an existing TLS identity

```sh
se050ctl tls-key-info -b 0 --profile test --identity 0 --slot A
```

Use a key whose attestation validation already succeeds. Do not generate a new key through the provider.

### 2. Resolve the provider URI

```sh
KEY_URI=$(se050ctl tls-key-ref --profile test --identity 0 --slot A)
echo "$KEY_URI"
```

Expected:

```text
nxp:0x30000200
```

### 3. Load the provider

Adjust the provider path as installed on the target.

```sh
openssl list -providers \
  -provider /usr/local/lib/libsssProvider.so \
  -provider default
```

Both the NXP and default providers must load.

### 4. ECDSA sign with the existing SE050 key

```sh
printf 'se050 provider test\n' > provider-input.txt

openssl pkeyutl \
  --provider /usr/local/lib/libsssProvider.so \
  --provider default \
  -inkey "$KEY_URI" \
  -sign \
  -rawin \
  -in provider-input.txt \
  -out provider-signature.der \
  -digest sha256
```

Success proves that the NXP provider resolves the existing Object ID provisioned by `se050_nim` and performs ECDSA signing in the SE050.

If the default provider is loaded first and NXP ECDSA is not selected, use the upstream property query:

```text
?nxp_prov.signature.ecdsa=yes
```

## Step 5 completion criteria

- Build the NXP provider for the target architecture
- OpenSSL 3 can load `libsssProvider.so`
- `EX_SSS_BOOT_SSS_PORT` reaches the target SE050
- The provider accepts the `nxp:0x...` URI from `se050ctl tls-key-ref`
- ECDSA signing succeeds through the provider using an existing TLS identity key
- Key generation remains owned by `se050_nim`, not the provider

The next step uses the same URI with `openssl req -new -key nxp:...` to generate and verify a CSR.


## CSR generation and public-key matching

A reference-key PEM is not required to create a CSR from a TLS identity key.
Pass the NXP Provider Object-ID URI directly to `openssl req`.

The following example uses test / identity 0 / slot A.

```sh
export EX_SSS_BOOT_SSS_PORT=/dev/i2c-0:0x48
PROVIDER=/usr/local/lib/libsssProvider.so
KEY_URI=$(se050ctl tls-key-ref --profile test --identity 0 --slot A)

se050ctl tls-key-pubkey \
  -b 0 \
  --profile test \
  --identity 0 \
  --slot A \
  --format spki-der \
  --out se050-public.der

openssl req -new \
  --provider "$PROVIDER" \
  --provider default \
  -key "$KEY_URI" \
  -subj "/CN=se050-local-test" \
  -out device.csr
```

Verify the CSR signature itself:

```sh
openssl req -in device.csr -noout -verify
```

Then extract the CSR SubjectPublicKeyInfo in DER and compare it byte-for-byte
with the attestation-validated SE050 public key:

```sh
openssl req -in device.csr -pubkey -noout | \
  openssl pkey -pubin -outform DER -out csr-public.der

cmp se050-public.der csr-public.der
```

A zero exit status from `cmp` proves that the CSR contains the public key of
the selected SE050 TLS identity object. No private-key file is created during
this flow.

## Local mutual-TLS integration test

See `docs/local-mtls-test.md` for real TLS client-authentication validation.
