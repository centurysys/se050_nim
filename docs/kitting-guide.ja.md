# SE050キッティングガイド

この文書は、`se050-kitting-export`でAttestation付きCSVを生成し、`se050ctl kitting-verify`またはライブラリAPIで検証する流れをまとめます。

## 現在の実装範囲

実装済み:

- Applet 7.2.xのReadObject-with-Attestation
- NXP個体証明書とAttestation署名の検証
- test firmware KEX鍵`0x30000100`の作成・再利用
- production firmware KEX鍵`0x20000100`の固定Policy生成経路
- 複数機器CSVへの安全な追加と冪等な再実行
- CSV recordのオフライン暗号学的検証
- CSVとローカル実機の照合

未実装:

- production鍵の削除不能・上書き不能実機試験
- SE050を必要としないPC専用CSV検証CLI
- firmware envelope生成、HKDF、AES-GCM、復号
- 複数プロセス同時追記用file lockと明示的`fsync()`

## 信頼の流れ

```text
NXP Attestation ECC Root
  └─ NXP Attestation ECC Intermediate
       └─ SE050個体証明書 0xF0000013
            └─ Attestation鍵 0xF0000012
                 └─ firmware KEX objectの公開鍵・属性へ署名
```

RootとIntermediateは以下に置き、`staticRead()`でバイナリへ組み込みます。

```text
src/se050_nim/certs/nxp-attestation-ecc-root.der
src/se050_nim/certs/nxp-attestation-ecc-intermediate.der
```

キッティング検証では、呼び出し側が別のRoot CAへ差し替えることはできません。診断用`se050ctl attest-verify`だけは、CA更新調査などのため外部DERを明示指定します。

## Profile

| Profile | Object ID | Curve/type | Policy | Lifecycle | CLI |
|---|---:|---|---:|---|---|
| `test` | `0x30000100` | P-256 / `0x29` | `0x04240000` | KA/READ/DELETE、上書き不可 | 実装済み |
| `production` | `0x20000100` | P-256 / `0x29` | `0x04200000` | KA/READ、削除・上書き不可 | CLI実装済み、実機試験待ち |

`test`はproduction相当のKA/READ権限にDELETEだけを追加しています。既存鍵を同じObject IDへ上書き・再生成する権限はありません。

## Board serial

基板serialは常に次のDevice Tree propertyから読みます。

```text
/proc/device-tree/board/serialno
```

ASCII数字だけを許可し、末尾のNUL/CR/LFだけを除去します。先頭ゼロは保持します。手入力によるserial overrideはありません。

SE050自身は基板serialを知りません。Exporterはserial、作成時刻、profile、nonceから16-byte freshnessを導出し、そのfreshnessをSE050のAttestation署名へ含めます。したがってCSV内のserialを後から変更すると署名検証に失敗します。

ただし、キッティング時点でDevice Treeに誤ったserialが書かれていた場合や、後からSE050を別基板へ載せ替えた場合まではオフライン検証だけでは判定できません。

## Test CSVの生成

```sh
se050-kitting-export test \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

処理順序:

1. `/proc/device-tree/board/serialno`を検証
2. Appletが7.2.xであることを確認
3. `0x30000100`がなければPolicy `0x04240000`で生成
4. NXP個体証明書`0xF0000013`、SE050 UID、公開鍵を取得
5. 既存CSVがあれば全recordをオフライン検証
6. 同一serial/profile/roleの有効なrecordがあれば実機と照合して`already valid`
7. 新しいnonceとfreshnessでReadObject-with-Attestationを実行
8. 証明書チェーン、署名、object属性、Policyを自己検証
9. 実機UID、object type/persistence、公開鍵を照合
10. CSVを同一directoryの一時ファイルへ書き、renameで置換
11. 書込み後に再読込・再検証

初回成功例:

```text
serialno: 11900000015
profile: test
key object id: 0x30000100
key created: yes
SE050 UID: 040050018641BAEE9BF71E042733D23E1F90
CSV record count: 1
CSV record: added
CSV path: /tmp/se050-kitting.csv
self-verification: valid
```

再実行成功例:

```text
serialno: 11900000015
profile: test
key object id: 0x30000100
key created: no
CSV record: already valid
CSV path: /tmp/se050-kitting.csv
```

## Production CSVの生成

`production`は固定Object ID `0x20000100`へ、KA/READだけを許可するPolicy `0x04200000`でP-256鍵を内部生成します。DELETE、WRITE、GEN権限は付与しません。

```sh
se050-kitting-export production \
  -b 0 \
  --append /tmp/se050-kitting.csv
```

この操作は不可逆です。最初の実機試験は出荷しない評価個体で実施してください。

Exporterは、鍵生成前に次の可逆な確認を完了します。

1. board serialとApplet version
2. NXP個体証明書の読取りと組み込みTrust Storeでのchain検証
3. SE050 UIDの読取り
4. 既存CSV全recordのオフライン検証
5. 同じserial/profileのCSV recordがある場合、対象Objectも存在すること

対象Objectが存在しない場合だけproduction鍵を生成します。既存Objectがある場合は削除・上書きせず再利用し、Attestationでtype、origin、Policy、公開鍵を検証します。一致しない場合は停止します。

鍵生成後にCSV書込みなどで失敗しても、次回実行では既存鍵を再利用してAttestationとCSV生成をやり直せます。

## 旧development鍵が残っている場合

汎用`se050ctl keygen`のPolicyは`0x043C0000`です。これで`0x30000100`を作った場合、Exporterは次のように拒否します。

```text
signed policy header 0x043C0000 is the generic development policy;
recreate 0x30000100 with the kitting test policy 0x04240000
```

Test objectであることを確認してから削除します。

```sh
se050ctl delete -b 0 --area dev --index 0x100
```

その後Exporterを再実行すると、正しいPolicyで作成されます。Exporter自身はPolicy不一致の既存鍵を自動削除しません。

## CSV format

Headerは固定です。

```text
serialno,format_version,profile,created_at,key_role,se050_uid,key_object_id,nonce,public_key,attestation_cert,attestation
```

| Field | 内容 |
|---|---|
| `serialno` | Device Treeの基板serial |
| `format_version` | 現在は`1` |
| `profile` | `test`または`production` |
| `created_at` | UTC `YYYY-MM-DDTHH:MM:SSZ` |
| `key_role` | 現在は`firmware-kex` |
| `se050_uid` | SE050 UID |
| `key_object_id` | firmware KEX Object ID |
| `nonce` | 16-byte乱数 |
| `public_key` | 65-byte P-256非圧縮公開鍵 |
| `attestation_cert` | SE050個体証明書DER |
| `attestation` | request/response/signatureを保持するversion付きcontainer |

Binary fieldは厳密なBase64で保存します。論理キーは`serialno + profile + key_role`です。同じ論理キーに別UID、別Object ID、別公開鍵が存在する場合は競合として拒否し、自動上書きしません。

## オフライン検証

`verifyKittingRecord()` / `verifyKittingCsvRecord()`はI2Cへアクセスしません。PC上でも次を検証できます。

- CSV構造、Base64、timestamp、profile
- metadataから再導出したfreshness
- NXP Rootまでの個体証明書chain
- Applet 7.2 Attestation ECDSA署名
- signed object ID/type/origin/size/Policy
- signed SE050 UIDと公開鍵
- serialやrecord内容の改ざん

PCだけでは、現在その基板に同じSE050と鍵が載っているかは確認できません。ただし、信頼できる工場工程でExporterが自己検証まで成功したCSVを受け取り、DB取込み前にオフライン検証する用途には使用できます。

現在はPC専用CLIをまだ用意していないため、PC側ではライブラリAPIを使用します。

## ローカル実機検証

```sh
se050ctl kitting-verify \
  -b 0 \
  --input /tmp/se050-kitting.csv \
  --profile test
```

このコマンドはオフライン検証に加えて、次を現在の実機と比較します。

- `/proc/device-tree/board/serialno`
- SE050 UID
- Object type `EC_KEY_PAIR_NIST_P256`
- persistent indicator
- 公開鍵

`--profile`のCLI defaultは`production`です。Test CSVを確認するときは`--profile test`を指定し、production CSVはdefaultまたは`--profile production`で選択します。

## NXP個体証明書のBinaryFile差異

個体によって、`0xF0000013`のBinaryFile割当サイズが実際のDER証明書より大きく、末尾が`0x00`で埋められている場合があります。

実装はReadSizeでObject全体を読み、先頭DER SEQUENCEの自己記述長で証明書本体を切り出します。DER後方はすべて`0x00`の場合だけ許可し、非ゼロデータがあれば拒否します。

## CSV更新の耐久性

現状は同一directory内の一時ファイルへ全CSVを書き、renameで置換します。途中の部分書込みをreaderに見せないための対策です。

CSV writerの追加hardeningとして、次は未実装です。

- 複数process/端末の同時追記を防ぐfile lock
- temporary fileとdirectoryへの明示的`fsync()`

## 次の開発段階

現在のCSVに記録された個体別P-256公開鍵を、将来のfirmware envelope生成側で使用します。

```text
Kitting CSV / DB
  -> device public key
  -> server ephemeral P-256 ECDH
  -> HKDF-SHA256
  -> AES-256-GCMでrelease CEKをwrap
  -> 共通暗号化firmware + 個体別envelope
```
