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

この設計は、ドメインロジック、通信プロトコル、Ghidra API を分離します。

## モジュールの責務

### 1. `modules/domain`

ドメインモジュールは、コアサービスインターフェースとデータ転送モデルを定義します:
- サービスインターフェース: `ProgramService`, `MemoryService`, `ListingService`, `FunctionService`, `DataTypeService` など。
- モデルレコード: `AddressResource`, `InstructionResource`, `FunctionResource`, `Page` など。
- 例外定義: `DomainException`, `GlobalVariableConflictException`, `TransactionExecutionException` など。
- **制約**: このモジュールは Ghidra API クラスを一切インポートしてはなりません。

### 2. `modules/wire`

通信層モジュールは、統合されたメソッドカタログを管理します:
- `ApiRegistry` が全 53 個の公開ドット記法メソッドとその入出力スキーマを一元管理します。
- `JsonParser`、`JsonWriter`、`JsonUtil` が JSON を解析して整形します。
- `ApiContractGenerator` が `docs/api.md`, `docs/asyncapi.yaml`, `docs/mcp-tools.json` を生成します。
- **制約**: 型のない生の JSON マップはこの境界で完全に停止します。

### 3. `modules/runtime`

ランタイムモジュールは、リクエストのディスパッチとセッションライフサイクルを管理します:
- `AgentDispatcher` が各リクエストを対象のメソッドハンドラーへ送ります。
- リクエストを 1 件ずつ実行します。`DispatchBarrier` は実行中のリクエストを追跡し、シャットダウン中は新しいリクエストを拒否します。
- セッション状態を保持し、安全なグレースフルシャットダウンを調整します。
- **制約**: このモジュールは Ghidra クラスに一切依存しません。

### 4. `modules/adapter`

アダプターモジュールは、ドメインサービスインターフェースを Ghidra API に接続します:
- `GhidraSession` がアクティブなプログラム参照とトランザクションライフサイクルを管理します。
- 各種サービス実装がドメイン操作を Ghidra API 呼び出しに変換します。
- `GhidraServiceFactory` がすべてのサービス実装を作成します。
- **制約**: このモジュールとランチャーだけが Ghidra パッケージをインポートできます。

### 5. `modules/transport/websocket`

このモジュールは WebSocket トランスポートを実装します:
- `AgentWebSocketServer` が内蔵 WebSocket サーバーを実装します。
- `AgentClient` が WebSocket トランスポートを組み込みサーバーまたは `ws_url` への送信型クライアントとして実行します。
- `MessageEnvelope` が JSON-RPC 2.0 のリクエスト、レスポンス、エラーエンベロープを検証します。

### 6. `modules/transport/mcp`

このモジュールは Model Context Protocol を実装します:
- `McpHttpServer` がプロトコル `2026-07-28` に準拠する Streamable HTTP サーバーを実装します。
- `McpToolRegistry` が 52 個の公開メソッドを 14 個のドメインツールおよび `ghidra.help` にマッピングします。
  `interface.get` は公開しません。
- `ghidra-bridge://contracts/mcp-tools` にてツール規約リソースを提供します。

### 7. `modules/launcher`

ランチャーモジュールは、ブリッジを起動し、Ghidra スクリプトを生成します:
- `Bootstrap` が起動引数を解析し、指定されたトランスポートを開始します。
- ビルドシステムが `GhidraLauncher.java.template` から `Bridge.java` と `GhidraMcp.java` を生成します。
- ランタイムクラスを `ghidra-bridge.jar` にパッケージ化します。
- 送信型モードでは、接続が閉じるかホストプロセスが停止すると、セッションが終了します。
  JDK の WebSocket は、ホストが閉じた接続を常に報告するとは限りません。
  そのため、クライアントは 5 秒ごとにキープアライブの ping を送信します。
  ping が失敗するとセッションが終了します。
  次に、ブリッジはアクティブな分析をキャンセルし、プログラムを保存します。
  スクリプトが戻り、ヘッドレスの Ghidra が終了します。
  `exit_deadline_sec` 値は終了時間の上限を設定します。
  Ghidra が上限時間までに終了しない場合、`GracefulExit` が JVM を強制停止します。
  上限時間に実行中の保存処理は先に完了します。
  ホスト側に別のウォッチドッグプロセスは不要です。

## アーキテクチャ規則と検証

プロジェクトは、次の検査をアーキテクチャ境界に使用します:
- Gradle タスク `verifyArchitecture` が全モジュールのパッケージインポートを検査します。
- `modules/adapter` と `modules/launcher` だけが、名前が `ghidra.` で始まるパッケージをインポートできます。
- `verifyApiContracts` タスクは構築サンドボックスで契約を生成し、差分がある場合は失敗します。
- `./gradlew clean verify` を実行して、これらの規則を確認します。
