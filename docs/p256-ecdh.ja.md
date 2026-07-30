# P-256 ECDHメモ

この文書は、`se050_nim`を使うfirmware envelope向けの鍵共有方針をまとめます。

## 判断

SE050-backed key agreement primitiveとしてP-256 ECDHを使用します。

```text
SE050 device P-256 private key
  x
server ephemeral P-256 public key
  -> 32-byte ECDH shared secret
  -> HKDF-SHA256
  -> AES-256-GCM wrap/open key
```

raw ECDH shared secretをそのままAES keyとして使用しません。

## Device keyとキッティングCSV

Testキッティングでは、SE050内部で生成した`0x30000100`のP-256公開鍵をAttestation付きCSVへ保存します。将来のproduction profileは`0x20000100`を使用します。

Envelope生成側は、暗号学的検証を通過したCSVまたはDBから個体公開鍵を取得します。

```text
board serial
  -> verified kitting record
  -> SE050 UID + device P-256 public key
  -> per-device envelope
```

CSVが保持する公開鍵、Object ID、SE050 UID、Policy、基板serialはAttestation検証で結び付けられます。Production鍵生成CLIは実装済みですが、不可逆実機試験は未完了です。Envelope生成コードはまだ未実装です。

## 公開鍵形式

`readPublicKey`はP-256公開鍵を65-byteの非圧縮pointとして返します。

```text
0x04 || X(32) || Y(32)
```

`se050ctl derive --peer-public`もこの形式を要求します。

## Shared secret

P-256 ECDH shared secretは32 bytesです。

```text
A private x B public == B private x A public
```

## Smoke test

```sh
se050ctl delete -b 0 --area dev --index 0x110 || true
se050ctl delete -b 0 --area dev --index 0x111 || true

se050ctl keygen -b 0 --area dev --index 0x110 --curve p256
se050ctl keygen -b 0 --area dev --index 0x111 --curve p256

se050ctl pubkey -b 0 --area dev --index 0x110 --out p256_a_pub.bin
se050ctl pubkey -b 0 --area dev --index 0x111 --out p256_b_pub.bin

se050ctl derive -b 0 --area dev --index 0x110 \
  --peer-public p256_b_pub.bin \
  --out p256_secret_ab.bin

se050ctl derive -b 0 --area dev --index 0x111 \
  --peer-public p256_a_pub.bin \
  --out p256_secret_ba.bin

sha256sum p256_secret_ab.bin p256_secret_ba.bin
cmp p256_secret_ab.bin p256_secret_ba.bin
```

期待値:

```text
public key:   65 bytes
shared secret: 32 bytes
```

## Envelopeレイヤ

`se050_nim`はSE050側ECDH primitiveとキッティング検証までを担当します。次の上位レイヤが以下を扱います。

```text
shared_secret = SE050 P-256 ECDH(device_private, server_ephemeral_public)
wrap_key      = HKDF-SHA256(shared_secret, salt, info/aad)
release_cek   = AES-256-GCM-open(wrapped_release_cek, wrap_key, nonce, aad, tag)
```

上位projectで固定するもの:

- envelope JSON/CBOR format
- algorithm/version identifier
- server ephemeral public key encoding
- HKDF salt/info
- AAD layout
- AES-GCM nonce/tag
- release CEK handling
- firmware body encryption/decryption
- firmware署名検証

## Envelope公開鍵field案

```json
{
  "alg": "P256-ECDH-HKDF-SHA256+A256GCM",
  "server_ephemeral_public_format": "p256-uncompressed",
  "server_ephemeral_public": "04...",
  "salt": "...",
  "aad": "...",
  "nonce": "...",
  "wrapped_release_cek": "...",
  "tag": "..."
}
```

Decode後のserver ephemeral public keyが正確に65 bytesで先頭`0x04`であることを、SE050へ渡す前に検証します。

## X25519

確認したApplet経路では:

- key generation成功
- Object type `0x69 EC_KEY_PAIR_MONT_DH_25519`
- 32-byte public key export成功
- deriveは`SW=0x6985`

raw、curve-prefix、nested TLVのpeer encodingを試してもderiveできなかったため、別経路で成功が確認されるまで製品本線から外します。

## Production note

現在実機確認済みなのは、削除可能なtest kitting鍵`0x30000100`までです。Production鍵`0x20000100`の不可逆生成CLIは実装済みですが、出荷しない評価個体での実機試験は未完了です。
