# se050_nim examples

このディレクトリには、`se050_nim` ライブラリを直接使う小さな実行例を置きます。
`se050ctl` の代替ではなく、ライブラリ利用方法を示すためのサンプルです。

## ビルド

リポジトリのルートから実行します。

```sh
nim c examples/read_uid.nim
nim c examples/random_bytes.nim
nim c examples/object_info.nim
nim c examples/p256_keygen_pubkey.nim
nim c examples/p256_derive_secret.nim
```

既存の `examples/config.nims` により、`../src` が Nim の module search path に追加されます。

## サンプル実行

```sh
# /dev/i2c-0 の SE050 UID を読む
./examples/read_uid 0

# 32 bytes の乱数を生成する
./examples/random_bytes 0 32

# 内蔵 UID object を確認する
./examples/object_info 0 0x7FFF0206

# dev index 0x110 に P-256 key pair を生成し、公開鍵を書き出す
./examples/p256_keygen_pubkey 0 0x110 p256_110_pub.bin

# dev key pair 2組を生成または再利用し、P-256 ECDH を双方向で確認する
./examples/p256_derive_secret 0 0x110 0x111
```

## 安全方針

書き込みを行うサンプルは、development object range だけを使います。

```text
0x30000000..0x3000FFFF
```

vendor / customer / NXP / internal range には書き込みません。
production provisioning は、one-time / no-delete policy を扱う別ツールとして実装する想定です。

## X25519

テスト済み環境では、X25519 の key generation と public key export は動作しましたが、X25519 derive は SE050 applet 7.2.0 の確認経路では成功していません。
そのため、examples は実機確認済みの P-256 ECDH を中心にしています。
