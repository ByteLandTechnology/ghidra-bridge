# 開発ガイド (Development Guide)

本ガイドでは、Ghidra Bridge コードベースのビルド、拡張、および検証手順について説明します。

## 前提条件

- **Java Development Kit**: JDK 21 が必須です。
- **Ghidra**: アダプターのコンパイルと MCP テストの実行には、Ghidra 12.1 以降が必要です。
- **環境設定**: `GHIDRA_INSTALL_DIR` 環境変数に Ghidra のインストールパスを設定してください。

Gradle は次の優先順序で Ghidra のインストールパスを解決します:
1. コマンドライン引数 `-PghidraInstallDir`。
2. 環境変数 `GHIDRA_INSTALL_DIR`。
3. システム `PATH` に存在する `ghidraRun` 実行可能ファイル。
4. Homebrew でインストールされた Ghidra。
5. システム `PATH` に存在する `analyzeHeadless` 実行可能ファイル。
6. ローカルマシンの標準的なインストールディレクトリ。

## Gradle ワークフロー

常にリポジトリに含まれる Gradle Wrapper を使用してください:

```bash
# 配布用スクリプトと JAR のビルド
./gradlew buildGhidraScript

# すべての検証チェックを実行
./gradlew --no-daemon clean verify
```

`buildGhidraScript` タスクは `build/ghidra-script/` 配下に次の 3 ファイルを生成します:
- `Bridge.java`
- `GhidraMcp.java`
- `ghidra-bridge.jar`

## API 操作の追加または変更手順

公開インターフェースを変更する際は、次の手順に従ってください:

### ステップ 1: ドメインモデルの更新

`modules/domain` 内にサービスメソッドとデータ型を定義します。
ドメインインターフェースは Ghidra API から完全に独立させ、Ghidra の型を漏洩させないでください。

### ステップ 2: Ghidra アダプターの実装

`modules/adapter` 内でサービスメソッドを実装します。
Ghidra の内部データ構造を型付けされたドメインレコードに変換します。
変更を伴う操作には、`GhidraSession` を使用してトランザクションを管理します。

### ステップ 3: Wire モジュールでのメソッド登録

`modules/wire` の `ApiRegistry` に新しい操作を登録します:
- `program.get` のような公開ドット記法名を付与します。
- 入力および出力のスキーマを定義します。
- ハンドラーをドメインサービスインターフェースに接続します。

### ステップ 4: 公開規約ファイルの再生成

規約生成タスクを実行します:

```bash
./gradlew generateApiContracts
```

このタスクは以下を自動的に再生成します:
- `docs/api.md`
- `docs/asyncapi.yaml`
- `docs/mcp-tools.json`

これらのファイルを手動で編集しないでください。
生成された内容と差分がある場合、ビルド検証タスクが失敗します。

## 品質ゲート

変更をコミットする前に、必ず検証スイートを実行してください:

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

検証タスクは以下を厳格に検査します:
- **アーキテクチャ境界**: `verifyArchitecture` により、adapter と launcher 以外での Ghidra クラスのインポートが禁止されます。
- **規約ドリフト検出**: `verifyApiContracts` により、ドキュメント規約とコードの一致が確認されます。
- **スクリプトコンパイル**: 生成された起動スクリプトが正常にコンパイルできることを確認します。
- **配布物**: `verifyDistribution` が `build/ghidra-script/` の内容を検証します。

## MCP テスト

`tests/` ディレクトリには MCP テストスイートがあります。
Ghidra ヘッドレスモードで、C/C++ サンプルバイナリに対してすべての MCP ツールを実行します。
実行方法は [tests/README.md](../../tests/README.md) を参照してください。
