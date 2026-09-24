# 协议规范 (Protocol Specification)

Ghidra Bridge 支持两种网络传输协议：WebSocket JSON-RPC 2.0 与 MCP Streamable HTTP `2026-07-28`。
统一注册表定义 53 个点分公共方法。
WebSocket 发布全部 53 个方法；MCP 发布 52 个方法，`interface.get` 仅限 WebSocket。

## WebSocket JSON-RPC 2.0

WebSocket 消息严格遵循 JSON-RPC 2.0 协议规范。
客户端通过全双工 Socket 长连接与桥接服务进行通信。

### 请求信封

客户端以标准 JSON 对象形式发送请求：

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "program.get",
  "params": {}
}
```

服务端对每个字段进行严格校验：
- `jsonrpc` 必须等于 `"2.0"`。
- `id` 必须为字符串或整数标识符。
- `method` 必须匹配 53 个公开点分方法之一。
- `params` 必须为符合该方法 Schema 定义的 JSON 对象。
- 服务端拒绝未知字段及非法数据类型。

### 就绪通知

当连接建立并准备就绪后，服务端发送就绪通知：

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

### 成功响应

请求执行成功后返回结果信封：

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

### 错误响应

请求执行失败后返回错误信封：

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

`target` 字段采用 RFC 6901 JSON Pointer 语法。
异常堆栈与内部实现细节绝不通过网络传递。

### 协议错误

对于格式错误的消息，服务端返回错误信封并保持连接：
- 非法 JSON 文本返回错误码 `-32700`。
- 不符合 JSON-RPC 2.0 请求格式的消息返回错误码 `-32600`。
- 方法执行失败返回错误码 `-32000`，`data` 字段携带桥接错误对象。

### 握手错误

在连接建立之前，服务端以 HTTP 状态码拒绝非法的升级请求：
- `400`：缺少升级头部、WebSocket 版本不受支持，或在查询字符串中携带 Token。
- `401`：缺少 Bearer Token 或 Token 无效。
- `404`：请求路径与配置的 `path` 不一致。
- `405`：升级请求未使用 GET 方法。
- `409`：已有其他客户端处于连接状态。

### WebSocket 关闭状态码

服务端使用以下状态码关闭连接：
- `1000`：正常关闭。
- `1001`：服务端停机。
- `1003`：客户端发送了分片文本消息或不受支持的帧。

## Model Context Protocol (MCP)

桥接服务实现 MCP Streamable HTTP 协议，版本号为 `2026-07-28`。
服务端不使用 MCP 会话，也不发送服务端推送事件（SSE）。

### HTTP 交互规范

MCP HTTP 服务端按以下规则处理入站请求：
- **POST**：分发处理入站 JSON-RPC 2.0 请求。
- **OPTIONS**：处理 CORS 预检请求并返回状态码 `204`。
- **GET**：服务端直接返回状态码 `405` 并附带 `Allow: POST, OPTIONS` 响应头。
- **其他方法**：服务端返回状态码 `405`。
- **Origin**：若请求携带的 `Origin` 头部既不是回环主机也不是配置的 `host`，返回状态码 `403`。
- **内容类型**：POST 请求必须发送 `Content-Type: application/json`，否则返回状态码 `415`。
- **通知**：不含 `id` 的请求返回状态码 `202`，且不含响应体。

### 请求元数据

每个 POST 请求都必须在 `params._meta` 中携带 MCP 元数据：

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

每个 POST 请求还必须发送以下 HTTP 头部：
- `MCP-Protocol-Version`：与 `io.modelcontextprotocol/protocolVersion` 的值相同。
- `Mcp-Method`：与 JSON-RPC 的 `method` 相同。
- `Mcp-Name`：`tools/call` 时为工具名，`resources/read` 时为资源 URI；其他方法不使用该头部。

对于非纯 ASCII 文本，头部值可以使用 `=?base64?<base64 文本>?=` 形式。

元数据不合法时，服务端返回以下错误：
- 缺少 `_meta` 字段：HTTP `400`，错误码 `-32602`。
- 协议版本不受支持：HTTP `400`，错误码 `-32022`，`data` 字段列出支持的版本。
- 头部与请求体不一致：HTTP `400`，错误码 `-32020`。

### 支持的 MCP 方法

服务端实现以下 MCP 方法：
- `server/discover`：返回服务端标识与支持的能力特性。
- `ping`：探测健康状态并返回完成标志。
- `tools/list`：返回全部 15 个工具的 Schema 定义。
- `tools/call`：执行具体的工具操作并返回结构化内容。
- `resources/list`：列出可用资源，包括 `ghidra-bridge://contracts/mcp-tools`。
- `resources/read`：读取资源内容。
- `resources/templates/list`：返回空模板列表。

其他方法返回 HTTP `404`，错误码 `-32601`。
所有成功结果均包含 `"resultType": "complete"`。

### 工具调用规范

MCP 将操作组织为 15 个工具：
- `ghidra.help`：发现领域、列出可用操作及查看操作 Schema。
- 14 个领域工具：`ghidra.bridge`、`ghidra.program`、`ghidra.address`、`ghidra.memory`、`ghidra.listing`、`ghidra.global_variable`、`ghidra.function`、`ghidra.analysis`、`ghidra.decompilation`、`ghidra.symbol`、`ghidra.reference`、`ghidra.comment`、`ghidra.data_type`、`ghidra.batch`。

领域工具共公开 52 个方法。`interface.get` 仅通过 WebSocket 提供。

`ghidra.help` 接受可选的 `domain` 与 `operation` 参数：
- 不带参数：返回领域工具列表。
- 仅 `domain`：返回该领域工具的操作名列表。
- `domain` 与 `operation`：返回该操作的方法名、描述、副作用、`inputSchema` 与 `outputSchema`。

调用具体操作时，向领域工具传递 `operation` 与 `params` 参数。
`operation` 的值是领域工具内的操作名，而不是点分方法名。
例如，`memory.read` 方法对应 `ghidra.memory` 的 `read` 操作：

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

响应同时包含纯文本内容与结构化内容：

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

操作失败时，服务端返回 HTTP `200` 且 `"isError": true`。
`structuredContent` 对象携带桥接错误，包含 `status`、`code`、`message`、`target` 与 `details`。
未知工具名返回 HTTP `400`，错误码 `-32602`。
未知操作，或 `operation` 与 `params` 之外的参数，返回工具错误。

## 认证与网络安全

- **默认回环**：监听器默认绑定 `127.0.0.1`。未设置 `token` 的回环监听器不需要认证。
- **外部绑定**：绑定至任何非回环网卡时必须提供 `token` 参数。
- **认证头部**：通过 `Authorization: Bearer <token>` 头部传递凭据。
- **拒绝 URL Token**：URL 查询参数中携带的 Token 会直接被 HTTP 400 拒绝。
- **日志脱敏**：安全 Token 绝不会在服务日志中打印。

## 有界地址扫描与分页游标

列表查询支持基于内存地址的有界扫描：
- `scan.range`：指定 `start` 和 `end` 地址范围。
- `scan.timeout_ms`：指定最大执行耗时预算（100 至 60000 毫秒），默认 1000。
- `page.limit`：单页最大条目限制（最高支持 1000 条）。

当查询在扫描完成前停止：
- 响应返回已匹配的条目。
- `scan.complete` 返回 `false`。
- `scan.stop_reason` 返回 `limit` 或 `timeout`。
- `next_cursor` 携带恢复游标。
- 下次请求将该游标作为 `page.cursor` 传递即可继续后续扫描。
