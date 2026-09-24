# Batch and Transactions

The `batch.execute` method executes multiple API operations in a single request.
It accepts a transaction mode and a list of 1 to 1000 items.

## Request Structure

A batch request supplies `transaction_mode` and an array of `items`:

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

The `transaction_mode` property is optional. The default is `per_item`.

Every item requires:
- `id`: A unique, non-blank string within the batch.
- `method`: A valid public dotted method name.
- `arguments`: An object matching the target method schema.

## Prevalidation Rules

The server validates the entire batch before executing any operation:
- It checks batch size limits between 1 and 1000 items.
- It validates that every `id` is unique.
- It decodes the arguments of every item with its target codec.
- Any validation failure rejects the entire request with HTTP status `400` and `code=validation_failed`.
- The `details.violations` array lists each problem with `target`, `code`, and `message`.
- Zero items execute if prevalidation fails.

### Prohibited Methods

Batches cannot nest these operations:
- `interface.get`
- `program.save`
- `analysis.start`
- `session.shutdown`
- `batch.execute`

Including any of these methods causes a prevalidation failure.

## Transaction Modes

The caller selects one of two transaction modes.

### 1. `all_or_none` (Atomic Execution)

- All items run inside one shared transaction.
- If all items succeed, the transaction commits.
- If any item fails, the transaction rolls back immediately.
- The server returns a top-level error with HTTP status `409` and `code=batch_rolled_back`.
- The `details.failed_item` property names the failed item. The `details.cause` property holds its error.
- Temporary modifications never persist to the program database.

### 2. `per_item` (Best-Effort Execution)

- Items execute sequentially in order.
- Each mutating item runs in its own transaction.
- Execution continues when an item fails.
- The response returns `{id, result}` rows and `{id, error}` rows.

## Analysis Concurrency

Batch requests inspect the active program state:
- If Ghidra background analysis runs, mutating batches fail immediately.
- The server returns HTTP status `409` with code `analysis_in_progress`.
- Read-only batches run normally during background analysis.

## Response Format

A successful batch execution returns one row for each item, in request order:

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

In `per_item` mode, a failed item returns an `{id, error}` row instead of an `{id, result}` row.
