# バッチとトランザクション (Batch and Transactions)

`batch.execute` メソッドは、1 回のリクエストで複数の API 操作を実行します。
トランザクションモードと 1 〜 1000 個の項目リストを受け取ります。

## リクエスト構造

バッチリクエストは `transaction_mode` と `items` 配列を指定します:

```json
{
  "transaction_mode": "all_or_none",
  "items": [
    {
      "id": "step-1",
      "method": "comment.create",
      "arguments": {
        "resource": {
          "address": "ram:00101000",
          "type": "plate",
          "text": "Entry point banner"
        }
      }
    },
    {
      "id": "step-2",
      "method": "symbol.patch",
      "arguments": {
        "selector": {"id": "1234"},
        "patch": {"name": "main_entry"}
      }
    }
  ]
}
```

`transaction_mode` プロパティは省略可能です。デフォルトは `per_item` です。

すべての項目で以下が必須です:
- `id`: バッチ内で一意な空でない文字列。
- `method`: 有効な公開ドット記法メソッド名。
- `arguments`: 対象メソッドのスキーマに合致する引数オブジェクト。

## 事前検証ルール

サーバーはいずれの操作を実行する前にも、バッチ全体を事前検証します:
- 項目数が 1 〜 1000 の範囲内であることを確認します。
- すべての `id` が重複していないことを確認します。
- 対象メソッドのコーデックを用いて全項目の `arguments` をデコードします。
- 形式や引数の検証に失敗した場合、リクエスト全体を HTTP ステータス `400` と `code=validation_failed` で拒否します。
- `details.violations` 配列に各問題の `target`、`code`、`message` が格納されます。
- 事前検証に失敗した場合、項目は 1 つも実行されません。

### ネストが禁止されているメソッド

バッチ内へのネストが禁止されているメソッド:
- `interface.get`
- `program.save`
- `analysis.start`
- `session.shutdown`
- `batch.execute`

上記メソッドを含めると事前検証エラーとなります。

## トランザクションモード

呼び出し元は 2 つのトランザクションモードのいずれかを選択します。

### 1. `all_or_none` (アトミック実行)

- すべての項目が単一の共有トランザクション内で実行されます。
- すべての項目が成功した場合にのみトランザクションがコミットされます。
- いずれか 1 つの項目が失敗した場合、トランザクションは直ちにロールバックされます。
- サーバーは HTTP ステータス `409` と `code=batch_rolled_back` を含むトップレベルエラーを返します。
- `details.failed_item` は失敗した項目を示し、`details.cause` にそのエラーが格納されます。
- 一時的な変更がプログラムデータベースに残ることはありません。

### 2. `per_item` (ベストエフォート実行)

- 項目は指定された順序で順次実行されます。
- 変更操作を伴う各項目は独立したトランザクションで実行されます。
- ある項目が失敗しても、以降の項目の処理は継続されます。
- レスポンスには `{id, result}` と `{id, error}` の双方が含まれます。

## 解析との並行性制御

バッチリクエストはアクティブなプログラムの状態を確認します:
- Ghidra のバックグラウンド解析が実行中の場合、変更を伴うバッチは直ちに拒否されます。
- サーバーは HTTP ステータス `409` とコード `analysis_in_progress` を返します。
- 読み取り専用のバッチはバックグラウンド解析中も正常に実行可能です。

## レスポンス形式

成功時のレスポンスは最小限のエンベロープ形式を返します:

```json
{
  "items": [
    {
      "id": "step-1",
      "result": {
        "address": "ram:00101000",
        "type": "plate",
        "text": "Entry point banner"
      }
    },
    {
      "id": "step-2",
      "result": {
        "id": "1234",
        "name": "main_entry",
        "address": "ram:00101000",
        "namespace": "Global",
        "primary": true,
        "source_type": "USER_DEFINED",
        "type": "Function"
      }
    }
  ]
}
```

`per_item` モードでは、失敗した項目は `{id, result}` 行の代わりに `{id, error}` 行を返します。
