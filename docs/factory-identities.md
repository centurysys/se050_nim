# NXP factory-provisioned cloud identities

Some SE050 variants contain NXP-provisioned private keys and matching X.509 certificates intended for cloud onboarding.

These credentials provide a short path to mTLS because the user does not need to generate a new SE050 key, create a CSR, or obtain a new client certificate before the first connection. The private key remains inside the SE050.

Use the managed `tls-keygen` identities instead when the product requires its own PKI, certificate rotation, multiple service identities, or customer-controlled certificate lifecycle.

## Known NXP factory cloud objects

| Kind | Identity | Key object | Certificate object |
|---|---:|---:|---:|
| ECC P-256 | 0 | `0xF0000100` | `0xF0000101` |
| ECC P-256 | 1 | `0xF0000102` | `0xF0000103` |
| RSA-2048 | 0 | `0xF0000110` | `0xF0000111` |
| RSA-2048 | 1 | `0xF0000112` | `0xF0000113` |

The exact provisioning depends on the SE050 variant/configuration. Inspect the target first:

```sh
se050ctl factory-list -b 0
```

The command is read-only and reports presence and `ReadType` information for the known cloud credentials and the NXP attestation objects.

## Short onboarding path

For ECC identity 0:

```sh
se050ctl factory-cert \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device.crt

KEY_URI=$(se050ctl factory-key-ref --kind ecc --identity 0)
```

The resulting URI is normally:

```text
nxp:0xF0000100
```

The factory key can then be used directly through the NXP OpenSSL Provider without a private-key file.

```sh
openssl pkeyutl \
  -provider /usr/local/lib/libsssProvider.so \
  -provider default \
  -inkey "$KEY_URI" \
  -sign \
  -rawin \
  -digest sha256 \
  -in test.txt \
  -out signature.der
```

## Public-key export

`factory-pubkey` extracts SubjectPublicKeyInfo from the factory X.509 certificate and supports ECC and RSA certificates.

```sh
se050ctl factory-pubkey \
  -b 0 \
  --kind ecc \
  --identity 0 \
  --format pem \
  --out device-public.pem
```

## RSA credentials

Use `--kind rsa` when the target variant contains the RSA factory credentials.

```sh
se050ctl factory-cert -b 0 --kind rsa --identity 0 --out device-rsa.crt
se050ctl factory-key-ref --kind rsa --identity 0
```

P-256 is normally preferable for a new deployment because its public keys, signatures, and certificates are smaller while providing stronger classical security than RSA-2048. RSA remains useful for compatibility with existing PKI and software.

## Hardware validation

`tools/se050_factory_identity_test.sh` exercises certificate export, public-key extraction, NXP OpenSSL Provider signing, and verification with the certificate public key for one selected factory identity.

```sh
./tools/se050_factory_identity_test.sh \
  --se050ctl ./se050ctl \
  --provider /usr/local/lib/libsssProvider.so \
  --kind ecc \
  --identity 0
```

A final `factory identity test: PASS` verifies that:

- the factory certificate can be read from the SE050 BinaryFile,
- `factory-pubkey` matches the SubjectPublicKeyInfo extracted by OpenSSL,
- the NXP Provider can use the factory key Object through its `nxp:0x...` URI,
- a signature made by the SE050-resident factory private key verifies with the factory certificate public key, and
- no private-key file is created.

Certificate time validity is reported, but NXP CA-chain validation, revocation status, and target-cloud acceptance are outside this local test.

## Lifecycle and safety

Factory credentials are NXP-managed identities. Check their certificate chain, validity, revocation status, and acceptance by the target service before deployment.

The factory commands are read-only. `se050_nim` does not provide factory-key generation, overwrite, or deletion through these commands, and the generic `se050ctl keygen` / `delete` mutation guards already reject the internal `0xF0000000..0xFFFFFFFF` range.

References:

- NXP AN12436: SE050 configurations
  https://www.nxp.com/docs/en/application-note/AN12436.pdf
- NXP Tech Blog: using SE050 through OpenSSL
  https://community.nxp.com/t5/NXP-Tech-Blog/セキュアエレメントSE05xの使用方法-OpenSSL経由でのSE050の使用-日本語ブログ/ba-p/2154251
