# Ghidra Bridge

[English](README.md) | [中文](README.zh-CN.md) | [日本語](README.ja-JP.md)

Ghidra Bridge は、実行中の Ghidra プログラムへのネットワークアクセスを提供します。
ランタイムは Java 21 で動作し、Ghidra 12.1 をサポートします。
WebSocket JSON-RPC 2.0 と MCP Streamable HTTP `2026-07-28` の 2 つのトランスポートを提供します。
ランタイム JAR はサードパーティ製ライブラリへの依存が一切ありません。

## 主な機能

- **デュアルトランスポート**: WebSocket JSON-RPC 2.0 または MCP Streamable HTTP 経由で Ghidra にアクセスできます。
- **統一されたメソッドカタログ**: 型定義された単一のレジストリが 53 個のドット記法メソッドを定義します。WebSocket は 53 個すべてを公開し、MCP はそのうち 52 個を公開します（`interface.get` は WebSocket 専用）。
- **有界アドレススキャン**: アドレス順のリスト取得において、協調的なタイムアウト処理とカーソルベースのページネーションをサポートします。
- **アトミックトランザクション**: バッチ処理をサポートし、エラー発生時は自動的にロールバックします。
- **ヘッドレスモード**: GUI を起動することなく、Ghidra のヘッドレスモードで実行できます。

## スクリプトのビルド

`GHIDRA_INSTALL_DIR` 環境変数に Ghidra のインストールパスを設定します。
次に、Gradle Wrapper を使用してスクリプトをビルドします:

```bash
./gradlew buildGhidraScript
```

ビルドタスクにより、`build/ghidra-script/` 配下に次の 3 つのファイルが生成されます:

```text
Bridge.java
GhidraMcp.java
ghidra-bridge.jar
```

これら 3 つのファイルは同じディレクトリに保持してください。
スクリプトローダーは、自身のファイルパスからの相対パスで `ghidra-bridge.jar` を検索します。

## ブリッジの起動

### Ghidra GUI での実行

1. Ghidra CodeBrowser で対象のバイナリを開きます。
2. Script Manager（スクリプトマネージャ）ウィンドウを開きます。
3. スクリプトパス一覧に `build/ghidra-script/` を追加します。
4. `Bridge.java`（WebSocket）または `GhidraMcp.java`（MCP）を実行します。
5. プロンプトウィンドウに設定引数を入力します。

### Ghidra ヘッドレスモードでの実行

`GhidraMcp.java` または `Bridge.java` をヘッドレスモードのポストスクリプトとして実行できます。
プロジェクトディレクトリを作成し、対象のバイナリをインポートして解析を実行します。
`.cache` などのドットで始まるディレクトリ名をプロジェクトパスに使用しないでください。

```bash
mkdir -p /path/to/projects
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects demo \
  -import /path/to/target_binary \
  -scriptPath "$PWD/build/ghidra-script" \
  -postScript GhidraMcp.java host=127.0.0.1 port=8766 path=/mcp session_id=demo
```

ポストスクリプトは、プロセスが停止されるまでリクエストの処理を継続します。
既存のプロジェクトファイルを再解析なしで開くには、`-process` と `-noanalysis` を使用します:

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects demo \
  -process target_binary -noanalysis \
  -scriptPath "$PWD/build/ghidra-script" \
  -postScript GhidraMcp.java host=127.0.0.1 port=8766 path=/mcp session_id=demo
```

## 設定パラメータ

ブリッジの設定には厳密な `key=value` 形式を使用します。
未知の引数、重複した引数、キャメルケースのキーは拒否されます。

```text
# 内蔵 WebSocket サーバー
host=127.0.0.1 port=8765 path=/ws/agent session_id=demo

# 送信型 WebSocket クライアント
ws_url=ws://127.0.0.1:8765/ws/agent session_id=demo token=secret

# MCP HTTP サーバー
host=127.0.0.1 port=8766 path=/mcp session_id=demo token=secret

# 独自のツール名を持つ 2 つ目の MCP HTTP サーバー
host=127.0.0.1 port=8767 path=/mcp session_id=other tool_prefix=other
```

### パラメータ仕様

| パラメータ | デフォルト値 | 説明 |
|---|---|---|
| `host` | `127.0.0.1` | リッスンするローカルネットワークインターフェースのアドレス。 |
| `port` | `8765` (WS) / `8766` (MCP) | HTTP または WebSocket サーバーの TCP ポート番号。WebSocket は `ws_url` 未指定時のみデフォルト値を使用します。 |
| `path` | `/ws/agent` (WS) / `/mcp` (MCP) | リクエストディスパッチ用の URL パスエンドポイント。 |
| `session_id` | プログラム名 | 現在のアクティブセッションを一意に識別する文字列。 |
| `token` | *(なし)* | Bearer 認証用の共有シークレットトークン。 |
| `ws_url` | *(なし)* | 送信型クライアントとして接続する際のリモート WebSocket URL。 |
| `tool_prefix` | `ghidra` | MCP 専用。すべてのツール名の先頭部分（`ghidra.program` の `ghidra` など）。1 つのクライアントが複数のサーバーに接続する場合、サーバーごとに異なる値を指定します。 |
| `jar` | *(自動)* | `ghidra-bridge.jar` をスクリプトと別ディレクトリに配置した場合のパス。 |
| `exit_deadline_sec` | *(なし)* | 送信型のみ。セッション終了後、この秒数以内に Ghidra が終了しない場合に JVM を強制停止します。その時点で実行中の保存は先に完了します。ホストが起動するヘッドレスの Ghidra にのみ使用してください。 |

## セキュリティ規定

ブリッジは厳格なセキュリティ境界を適用します:

- **ループバック既定**: リスナーはデフォルトで `127.0.0.1` にバインドされます。
- **トークン必須**: ループバック以外のインターフェースにバインドする場合、`token` の指定が必須です。
- **Bearer ヘッダー**: 受信リクエストは `Authorization: Bearer <token>` を送信する必要があります。
- **URL トークンの拒否**: URL クエリ文字列に含まれるトークンは HTTP 400 で拒否されます。
- **ログの機密保護**: シークレットトークンがログファイルやコンソールに出力されることはありません。

## API とトランスポート仕様

公開 API には、`interface.get` から `batch.execute` まで 53 個のドット記法メソッドが存在します。

### WebSocket JSON-RPC 2.0

WebSocket では標準的な JSON-RPC 2.0 形式でリクエストを送信します:

```json
{"jsonrpc":"2.0","id":"r1","method":"program.get","params":{}}
```

`interface.get` を呼び出すことで、サポートされている全メソッドとスキーマを取得できます。

### Model Context Protocol (MCP)

MCP は Streamable HTTP を介して、`interface.get` を除く同じ操作を 15 個のツールとして公開します:
- `ghidra.help`: ドメインの探索、操作一覧の取得、スキーマの確認。
- 14 個のドメインツール: `ghidra.program`, `ghidra.memory`, `ghidra.function`, `ghidra.listing` など。

操作を呼び出すには、ドメインツール内の操作名とパラメータを渡します。
たとえば、`program.get` メソッドは `ghidra.program` の `get` 操作です:

```json
{
  "name": "ghidra.program",
  "arguments": {
    "operation": "get",
    "params": {}
  }
}
```

`2026-07-28` のリクエストには MCP メタデータとヘッダーも必要です。`initialize` を使用する `2025-06-18` と `2025-11-25` のクライアントにも対応しています。詳細は[プロトコル仕様](docs/ja/protocol.md)を参照してください。

完全な MCP ツールスキーマは `ghidra-bridge://contracts/mcp-tools` リソースからも取得可能です。

## ドキュメント一覧

- [概要 (Overview)](docs/ja/overview.md): システムコンセプト、並行性モデル、クエリパターン。
- [アーキテクチャ (Architecture)](docs/ja/architecture.md): モジュール境界と依存関係グラフ。
- [プロトコル仕様 (Protocol)](docs/ja/protocol.md): JSON-RPC エンベロープ、MCP エンドポイント、エラー形式。
- [バッチとトランザクション (Batch and Transactions)](docs/ja/batch-and-transactions.md): アトミックバッチ処理とトランザクション制御。
- [開発ガイド (Development)](docs/ja/development.md): 開発環境構築、ワークフロー、品質ゲート。
- [メソッドリファレンス (Method Reference)](docs/api.md): 全 53 メソッドの一覧とスキーマ。
- [AsyncAPI 規約 (AsyncAPI)](docs/asyncapi.yaml): WebSocket の正式な規約。
- [MCP ツール定義 (MCP Tools)](docs/mcp-tools.json): MCP ツールの正式な定義。

## ビルドの検証

変更をコミットする前に、すべての検証スイートを実行してください:

```bash
./gradlew --no-daemon clean verify
```

`verify` タスクは以下を厳格に検査します:
- アーキテクチャ分離ルールの遵守。
- 生成された API コントラクトとの差分チェック。
- 生成スクリプトのビルドとコンパイル。

[tests/](tests/README.md) の MCP テストスイートは、Ghidra ヘッドレスモードですべての MCP ツールを実行します。
