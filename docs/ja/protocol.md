# プロトコル仕様 (Protocol Specification)

Ghidra Bridge は、WebSocket JSON-RPC 2.0 と MCP Streamable HTTP `2026-07-28` の 2 つのトランスポートをサポートします。
統一レジストリは 53 個の公開ドット記法メソッドを定義します。
WebSocket は 53 個すべてを提供し、MCP は 52 個を提供します（`interface.get` は WebSocket 専用）。

## WebSocket JSON-RPC 2.0

WebSocket メッセージは JSON-RPC 2.0 仕様に準拠します。
クライアントは全二重ソケット接続経由でブリッジと通信します。

### リクエストエンベロープ

クライアントは JSON オブジェクトとしてリクエストを送信します:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "program.get",
  "params": {}
}
```

サーバーは各フィールドを厳格に検証します:
- `jsonrpc` は `"2.0"` である必要があります。
- `id` は文字列または整数の識別子である必要があります。
- `method` は 53 個の公開ドット記法メソッドのいずれかと一致する必要があります。
- `params` はメソッドのスキーマに合致する JSON オブジェクトである必要があります。
- 未知のフィールドや不正なデータ型は拒否されます。

### 準備完了通知 (Ready Notification)

接続が確立されて準備が完了すると、サーバーは準備完了通知を送信します:

```json
{
  "jsonrpc": "2.0",
  "method": "ghidra.ready",
  "params": {
    "session_id": "demo",
    "program_name": "example.bin"
  }
}
```

### 成功レスポンス

リクエストが成功すると、結果エンベロープが返されます:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "result": {
    "name": "example.bin",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc"
  }
}
```

### エラーレスポンス

リクエストが失敗すると、エラーエンベロープが返されます:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "error": {
    "code": -32000,
    "message": "address not found",
    "data": {
      "status": 404,
      "code": "not_found",
      "message": "address not found",
      "target": "/params/selector/address",
      "details": {}
    }
  }
}
```

`target` プロパティは RFC 6901 JSON Pointer 形式を使用します。
スタックトレースや内部実装の例外詳細がネットワークへ漏洩することはありません。

### プロトコルエラー

不正なメッセージに対して、サーバーはエラーエンベロープを返し、ソケットを維持します:
- 不正な JSON テキストはコード `-32700` を返します。
- JSON-RPC 2.0 リクエストとして不正なメッセージはコード `-32600` を返します。
- メソッドの失敗はコード `-32000` を返します。`data` プロパティにブリッジエラーが格納されます。

### ハンドシェイクエラー

ソケット確立前に、サーバーは不正なアップグレードリクエストを HTTP ステータスで拒否します:
- `400`: アップグレードヘッダーの欠落、未対応の WebSocket バージョン、またはクエリ文字列内のトークン。
- `401`: Bearer トークンの欠落または不正。
- `404`: リクエストパスが設定された `path` と一致しない。
- `405`: アップグレードリクエストが GET ではない。
- `409`: 別のクライアントが既に接続している。

### WebSocket 切断コード

サーバーは次のステータスコードでソケットを切断します:
- `1000`: 正常終了。
- `1001`: サーバーのシャットダウン。
- `1003`: クライアントが分割テキストメッセージまたは未対応のフレームを送信した。

## Model Context Protocol (MCP)

ブリッジは MCP Streamable HTTP プロトコルバージョン `2026-07-28` を実装しています。
サーバーは MCP セッションを使用せず、サーバー送信イベント (SSE) も送信しません。

### HTTP リクエスト処理ルール

MCP HTTP サーバーは次のルールに従ってリクエストを処理します:
- **POST**: 受信した JSON-RPC 2.0 リクエストを処理します。
- **OPTIONS**: CORS プリフライトリクエストを処理し、ステータス `204` を返します。
- **GET**: ステータス `405` と `Allow: POST, OPTIONS` ヘッダーを返します。
- **その他のメソッド**: ステータス `405` を返します。
- **Origin**: `Origin` ヘッダーのホストがループバックでも設定済みの `host` でもない場合、ステータス `403` を返します。
- **Content-Type**: POST リクエストは `Content-Type: application/json` を送信する必要があります。それ以外はステータス `415` を返します。
- **通知**: `id` を持たないリクエストは、本文なしでステータス `202` を返します。

### リクエストメタデータ

すべての POST リクエストは `params._meta` に MCP メタデータを含める必要があります:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "ping",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "example-client", "version": "1.0.0"},
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

すべての POST リクエストは次の HTTP ヘッダーも送信する必要があります:
- `MCP-Protocol-Version`: `io.modelcontextprotocol/protocolVersion` と同じ値。
- `Mcp-Method`: JSON-RPC の `method` と同じ値。
- `Mcp-Name`: `tools/call` ではツール名、`resources/read` ではリソース URI。その他のメソッドでは使用しません。

ASCII 以外のテキストには `=?base64?<base64 テキスト>?=` 形式のヘッダー値を使用できます。

メタデータが不正な場合、サーバーは次のエラーを返します:
- `_meta` フィールドの欠落: HTTP `400`、コード `-32602`。
- 未対応のプロトコルバージョン: HTTP `400`、コード `-32022`。`data` プロパティに対応バージョンが格納されます。
- ヘッダーとリクエスト本文の不一致: HTTP `400`、コード `-32020`。

### サポートされる MCP メソッド

サーバーは次の MCP メソッドを実装しています:
- `server/discover`: サーバーの識別情報とサポート機能を返します。
- `ping`: 接続ヘルスチェックを実施し、完了ステータスを返します。
- `tools/list`: 全 15 個のツールのスキーマ定義を返します。
- `tools/call`: 指定されたツール操作を実行し、構造化コンテンツを返します。
- `resources/list`: `ghidra-bridge://contracts/mcp-tools` を含む利用可能なリソース一覧を返します。
- `resources/read`: リソースの内容を返します。
- `resources/templates/list`: 空のテンプレートリストを返します。

その他のメソッドは HTTP `404`、コード `-32601` を返します。
成功した結果にはすべて `"resultType": "complete"` が含まれます。

### ツール呼び出し規則

MCP は操作を 15 個のツールに分類します:
- `ghidra.help`: ドメインの探索、操作一覧の表示、スキーマの確認。
- 14 個のドメインツール: `ghidra.bridge`, `ghidra.program`, `ghidra.address`, `ghidra.memory`, `ghidra.listing`, `ghidra.global_variable`, `ghidra.function`, `ghidra.analysis`, `ghidra.decompilation`, `ghidra.symbol`, `ghidra.reference`, `ghidra.comment`, `ghidra.data_type`, `ghidra.batch`。

ドメインツールは 52 個のメソッドを公開します。`interface.get` は WebSocket 専用です。

`ghidra.help` は省略可能な `domain` と `operation` 引数を受け付けます:
- 引数なし: ドメインツールの一覧を返します。
- `domain` のみ: そのドメインツールの操作名一覧を返します。
- `domain` と `operation`: その操作のメソッド名、説明、副作用、`inputSchema`、`outputSchema` を返します。

操作を呼び出すには、対象のドメインツールに対して `operation` と `params` を渡します。
`operation` の値はドメインツール内の操作名であり、ドット記法のメソッド名ではありません。
たとえば、`memory.read` メソッドは `ghidra.memory` の `read` 操作です:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "example-client", "version": "1.0.0"},
      "io.modelcontextprotocol/clientCapabilities": {}
    },
    "name": "ghidra.memory",
    "arguments": {
      "operation": "read",
      "params": {
        "selector": {"address": "ram:00100000"},
        "length": 4
      }
    }
  }
}
```

レスポンスはテキストと構造化データの双方を返します:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "result": {
    "resultType": "complete",
    "content": [
      {
        "type": "text",
        "text": "{\"operation\":\"read\",\"result\":{\"address\":\"ram:00100000\",\"bytes\":{\"encoding\":\"hex\",\"data\":\"7f454c46\",\"length\":4}}}"
      }
    ],
    "structuredContent": {
      "operation": "read",
      "result": {
        "address": "ram:00100000",
        "bytes": {"encoding": "hex", "data": "7f454c46", "length": 4}
      }
    },
    "isError": false
  }
}
```

操作が失敗した場合、サーバーは HTTP `200` と `"isError": true` を返します。
`structuredContent` オブジェクトには `status`、`code`、`message`、`target`、`details` を持つブリッジエラーが格納されます。
未知のツール名は HTTP `400`、コード `-32602` を返します。
未知の操作、または `operation` と `params` 以外の引数はツールエラーを返します。

## 認証とセキュリティ規定

- **ループバック既定**: リスナーはデフォルトで `127.0.0.1` にバインドされます。`token` を設定していないループバックリスナーは認証不要です。
- **外部公開時の必須トークン**: 外部ネットワークインターフェースにバインドする場合、`token` が必須です。
- **Authorization ヘッダー**: 認証情報は `Authorization: Bearer <token>` 経由で送信します。
- **URL トークンの拒否**: クエリ文字列に含まれるトークンは HTTP 400 で拒否されます。
- **ログの保護**: シークレットトークンがログに出力されることはありません。

## 有界アドレススキャンとカーソル

一覧取得メソッドはメモリ範囲に対する有界スキャンをサポートします:
- `scan.range`: `start` および `end` アドレス境界を指定します。
- `scan.timeout_ms`: 100 〜 60000 ミリ秒の最大処理時間を指定します。デフォルトは 1000 です。
- `page.limit`: 1 ページあたりの最大取得件数（最大 1000 件）を指定します。

処理完了前に停止した場合:
- 収集済みの項目を返します。
- `scan.complete` は `false` を返します。
- `scan.stop_reason` は `limit` または `timeout` を返します。
- `next_cursor` に再開用トークンが格納されます。
- 次回のリクエストでこのトークンを `page.cursor` として渡すとスキャンを再開できます。
