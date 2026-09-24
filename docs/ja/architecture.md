# アーキテクチャ (Architecture)

Ghidra Bridge は、厳格な単方向依存関係を持つモジュラーアーキテクチャを採用しています。
すべてのソースモジュールは `modules/` ディレクトリ配下に配置されています。

## 依存関係グラフ

```text
modules/domain (サービスインターフェースとデータモデル)
       ▲
       └── modules/wire (メソッドレジストリと JSON コーデック)
                 ▲
                 └── modules/runtime (ディスパッチャとセッション制御)
                           ▲
                           ├── modules/transport/websocket (WebSocket JSON-RPC)
                           ├── modules/transport/mcp (MCP Streamable HTTP)
                           └── modules/adapter (Ghidra サービス実装)
                                     ▲
                                     └── modules/launcher (ブートストラップとスクリプト)
```

アダプターモジュールは `modules/domain` と `modules/wire` にも直接依存します。
ランチャーモジュールはアダプターと 2 つのトランスポートモジュールに依存します。

この設計により、ドメインロジック、通信プロトコル、Ghidra API 間の明確な関心の分離が保証されます。

## モジュールの責務

### 1. `modules/domain`

ドメインモジュールは、コアサービスインターフェースとデータ転送モデルを定義します:
- サービスインターフェース: `ProgramService`, `MemoryService`, `ListingService`, `FunctionService`, `DataTypeService` など。
- モデルレコード: `AddressResource`, `InstructionResource`, `FunctionResource`, `Page` など。
- 例外定義: `DomainException`, `GlobalVariableConflictException` など。
- **制約**: このモジュールは Ghidra API クラスを一切インポートしてはなりません。

### 2. `modules/wire`

通信層モジュールは、統合されたメソッドカタログを管理します:
- `ApiRegistry` が全 53 個の公開ドット記法メソッドとその入出力スキーマを一元管理します。
- `JsonParser`、`JsonWriter`、`JsonUtil` による軽量な JSON パースおよびシリアライズ機能を提供します。
- `ApiContractGenerator` が `docs/api.md`, `docs/asyncapi.yaml`, `docs/mcp-tools.json` を生成します。
- **制約**: 型のない生の JSON マップはこの境界で完全に停止します。

### 3. `modules/runtime`

ランタイムモジュールは、リクエストのディスパッチとセッションライフサイクルを管理します:
- `AgentDispatcher` がリクエストを受け取り、対象のメソッドハンドラーへルーティングします。
- リクエストを 1 件ずつ実行します。`DispatchBarrier` は実行中のリクエストを追跡し、シャットダウン中は新しいリクエストを拒否します。
- セッション状態を保持し、安全なグレースフルシャットダウンを調整します。
- **制約**: このモジュールは Ghidra クラスに一切依存しません。

### 4. `modules/adapter`

アダプターモジュールは、ドメインサービスインターフェースを Ghidra API に接続します:
- `GhidraSession` がアクティブなプログラム参照とトランザクションライフサイクルを管理します。
- 各種サービス実装がドメイン操作を Ghidra API 呼び出しに変換します。
- `GhidraServiceFactory` が全サービス実装の構成ファクトリとして機能します。
- **制約**: Ghidra クラスのインポートは、本モジュールおよびランチャーにのみ限定されます。

### 5. `modules/transport/websocket`

このモジュールは WebSocket トランスポートを実装します:
- `AgentWebSocketServer` が内蔵 WebSocket サーバーを実装します。
- `AgentClient` が WebSocket トランスポートを組み込みサーバーまたは `ws_url` への送信型クライアントとして実行します。
- `MessageEnvelope` が JSON-RPC 2.0 のリクエスト、レスポンス、エラーエンベロープを検証します。

### 6. `modules/transport/mcp`

このモジュールは Model Context Protocol を実装します:
- `McpHttpServer` がプロトコル `2026-07-28` に準拠した Streamable HTTP サーバーを実装します。
- `McpToolRegistry` が 52 個の公開メソッドを 14 個のドメインツールおよび `ghidra.help` に射影します。`interface.get` は公開しません。
- `ghidra-bridge://contracts/mcp-tools` にてツール規約リソースを提供します。

### 7. `modules/launcher`

ランチャーモジュールは、ブリッジの起動と Ghidra スクリプトの生成を担当します:
- `Bootstrap` が起動引数を解析し、指定されたトランスポートを開始します。
- ビルドシステムが `GhidraLauncher.java.template` から `Bridge.java` と `GhidraMcp.java` を生成します。
- コンパイルされたランタイムを単一の `ghidra-bridge.jar` としてパッケージ化します。

## アーキテクチャの機械的検証

プロジェクトはアーキテクチャ境界を機械的に検証します:
- Gradle タスク `verifyArchitecture` が全モジュールのパッケージインポートを検査します。
- `ghidra.` から始まるクラスのインポートは `modules/adapter` と `modules/launcher` のみに制限されます。
- `verifyApiContracts` タスクが規約ファイルを再生成し、差分を検知した場合はビルドを失敗させます。
- `./gradlew clean verify` を実行することで、これらすべての準拠性を確認できます。
