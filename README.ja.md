# Bonebed

Ruby gem のインストールや読み込み時に、ファイル、ネットワーク、外部コマンドへのアクセスを観測します。
記録を JSON に保存し、バージョン間の変化や、プロジェクトで許可した操作との差分を確認できます。

この文書は開発中のソースに対応しています。公開済みの 0.1.0 gem には未収録の機能があります。
変更点は [CHANGELOG](CHANGELOG.md)、未実装項目とリリース条件は [実装状況](docs/implementation-status.md) を参照してください。

## まずコンテナで観測する

Linux 5.5 以降、Ruby 3.2 以降、x86_64 または aarch64 が必要です。
macOS では Linux コンテナを使います。以下は、Docker と Ruby を利用できる開発者向けの手順です。
導入後は「目的に応じてコマンドを選ぶ」から必要な操作を探せます。

```sh
docker build -t bonebed:local .
BONEBED_IMAGE=bonebed:local bundle exec exe/bonebed --docker doctor
BONEBED_IMAGE=bonebed:local bundle exec exe/bonebed --docker dig rainbow --phase all --offline --strict
```

リリース用イメージはまだ公開されていないため、ここではソースからビルドします。
`--docker` は作業ディレクトリを読み取り専用、結果ディレクトリを読み書き可能でマウントします。
観測記録は `results/PHASE/GEM/` 以下に保存されます。

`--phase all` はパッケージを先に取得してから、使い捨ての環境でインストールと読み込みを観測します。
RubyGems プラグインを含む gem では、その読み込みも記録します。
対象プロセスには普段の環境変数を引き継がず、ホームと作業ディレクトリに偽の認証情報を用意します。

`--offline` は対象を専用のネットワーク名前空間で実行します。
環境の制約で作成できない場合は、観測対象の通信システムコールを拒否する方式に切り替え、その事実を記録します。
`--strict` を付けると、この切り替えを含む観測側のエラーでコマンドが失敗します。
観測前のパッケージ取得にはネットワークを使います。

## 目的に応じてコマンドを選ぶ

以下は Linux 上でのコマンド例です。macOS では同じコマンドを `--docker` 経由で実行してください。

| 目的 | コマンド |
| --- | --- |
| gem の読み込みを調べる | `bonebed dig json` |
| インストールから観測する | `bonebed dig rainbow --phase all --offline` |
| 3 回実行して変動を確認する | `bonebed dig rainbow --phase all --repeat 3` |
| gem の実行ファイルを調べる | `bonebed dig rake --phase exec --executable rake -- --version` |
| ロックファイルの依存を調べる | `bonebed survey --gemfile Gemfile.lock --phase all --jobs 2` |
| 保存済みの記録を読む | `bonebed report results --format md` |
| 2 つの観測記録を比べる | `bonebed diff BEFORE.json AFTER.json` |
| 保存済みの記録をポリシーで検査する | `bonebed check results --fail-on high` |
| 記録を静的サイトにまとめる | `bonebed dataset results --output site` |

単独の `require` 観測には、対象 gem と実行時の依存 gem がインストール済みである必要があります。
未インストールの場合は `--phase all` を使ってください。
`--repeat` の結果には、全サンプルで観測された操作と、一部だけで観測された操作が残ります。

## 観測結果と安全性の判断を分ける

Bonebed は、選んだ実行条件で見えた操作を記録します。未観測の操作が起きないことや、gem の安全性は保証しません。
システムコールの引数を読み取ってから実行が再開するまでに、対象が引数を書き換える余地もあります。
不明な gem は、秘密情報や重要な書き込み可能ファイルを置かない使い捨て環境で実行してください。

`.bonebed.yml` は実行後の記録を検査する設定です。対象の操作を制限したい場合は、別形式の設定を `--enforce FILE` に指定します。
これは Linux の Landlock を使う任意機能で、対応するファイル操作や TCP 通信を制限します。
設定例と制約は [ポリシー](docs/policies.md)、観測の限界は [脅威モデル](docs/threat-model.md) に記載しています。

終了コードは、成功が `0`、対象の失敗やタイムアウトが `1`、`--strict` による観測側の失敗が `2`、ポリシー違反が `3`、引数の誤りが `64` です。
対象が失敗しても観測記録は保存されます。対象側の `errors` と、観測側の `observer_errors` を確認してください。

## 詳しい仕様と問い合わせ先

「マニフェスト」は JSON の観測記録、「ベースライン」は差し引く起動時の通常動作を指します。
フィールドの意味は [マニフェスト仕様](docs/manifest.md)、全コマンドは [英語版 README](README.md) にあります。
[CI 連携](docs/ci.md)と[データセット運用](docs/dataset.md)も参照できます。

不具合や誤解を招く観測結果は [Issues](https://github.com/ydah/bonebed/issues) へ、機密情報を含む脆弱性の報告は [SECURITY.md](SECURITY.md) の窓口へお願いします。
開発時は `bin/dev bundle exec rake` でテストと書式検査を実行します。
