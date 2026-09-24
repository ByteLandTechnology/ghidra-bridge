# 批处理与事务 (Batch and Transactions)

`batch.execute` 方法允许在单次网络请求中执行多个 API 操作。
该方法接受指定的事务模式以及包含 1 至 1000 个条目的列表。

## 请求结构

批处理请求包含 `transaction_mode` 字段与 `items` 条目数组：

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

`transaction_mode` 为可选属性，默认值为 `per_item`。

每个条目必须包含以下字段：
- `id`：在当前批处理中唯一的非空字符串标识。
- `method`：有效的公开点分方法名。
- `arguments`：符合目标方法 Schema 定义的参数对象。

## 预校验规则

在执行任何操作之前，服务端会对整个批处理进行全面预校验：
- 校验批处理条目总数处于 1 至 1000 之间。
- 校验每个条目的 `id` 唯一且不重复。
- 使用目标方法的编解码器提前解码每个条目的 `arguments` 参数。
- 发现任何格式或参数校验错误时，将直接以 HTTP 状态码 `400` 及 `code=validation_failed` 拒绝整个请求。
- `details.violations` 数组列出每个问题的 `target`、`code` 与 `message`。
- 预校验失败时，没有任何条目会被执行。

### 禁用嵌套的方法

批处理中严禁嵌套以下操作：
- `interface.get`
- `program.save`
- `analysis.start`
- `session.shutdown`
- `batch.execute`

包含上述任一方法将导致预校验直接失败。

## 事务模式

调用方可选用以下两种事务模式之一：

### 1. `all_or_none`（原子事务模式）

- 所有条目在同一个共享的 Ghidra 事务中执行。
- 若所有条目均成功执行，事务统一提交。
- 若任一条目执行失败，整个事务立即回滚。
- 服务端返回顶层错误，HTTP 状态码为 `409`，错误码为 `code=batch_rolled_back`。
- `details.failed_item` 指明失败的条目，`details.cause` 携带其错误。
- 临时的修改绝不会持久化到程序数据库中。

### 2. `per_item`（尽力而为模式）

- 条目按声明顺序依次执行。
- 每个修改操作条目在独立的事务中运行。
- 单个条目失败后，后续条目仍会继续执行。
- 响应中同时包含 `{id, result}` 成功结果与 `{id, error}` 错误信息。

## 分析并发冲突控制

批处理请求会检查当前程序的后台分析状态：
- 若 Ghidra 正在运行后台自动分析，包含写操作的批处理将直接被拒绝。
- 服务端返回 HTTP 状态码 `409` 及错误码 `analysis_in_progress`。
- 纯读取操作的批处理在后台分析期间仍可正常执行。

## 响应格式

成功执行的批处理返回标准信封结果：

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

在 `per_item` 模式下，失败的条目返回 `{id, error}` 行，而不是 `{id, result}` 行。
