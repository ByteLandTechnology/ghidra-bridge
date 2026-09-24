# 概述 (Overview)

Ghidra Bridge 为正在运行的 Ghidra 程序提供网络访问。
该桥接支持两种网络传输协议：WebSocket JSON-RPC 2.0 与 MCP Streamable HTTP `2026-07-28`。
注册表定义 53 个公共点分方法，从 `interface.get` 到 `batch.execute`。
WebSocket 发布全部 53 个方法；MCP 发布 52 个方法，`interface.get` 仅限 WebSocket。
运行时 JAR 包不包含任何第三方依赖。

## 设计目标

- **统一目录**：所有操作、Schema 和处理器均集中在单一类型化方法注册表中。
- **协议对等**：WebSocket 与 MCP 共享相同的参数定义、返回值结构、错误信息及验证规则。
- **零外部依赖**：核心运行时与传输层仅使用标准 Java 21 平台库实现。
- **严格隔离**：Ghidra 专有 API 严格限定在适配器模块的领域服务接口后。

## 并发与会话模型

桥接服务在每个会话中绑定到一个活跃的 Ghidra 程序。
请求在单个分发队列中按顺序执行。
分发器在任意时刻仅执行一个操作。

Ghidra 的后台自动分析在独立线程中运行。
在后台分析运行期间：
- 读取操作保持可用。
- 修改操作将返回 HTTP 状态码 `409` 及错误码 `analysis_in_progress`。
- 启动新分析将返回状态码 `409` 及错误码 `analysis_already_running`。

## 通用请求模式

在两种传输协议中，各类方法均遵循标准的资源交互模式：

- **获取与删除 (Get/Delete)**：请求提供 `selector` 选择器对象，例如地址或标识符。
- **更新 (Update)**：请求提供 `selector` 对象及包含修改字段的 `patch` 补丁对象。
- **创建 (Create)**：请求提供包含初始属性的 `resource` 资源对象。
- **列表 (List)**：请求接受可选的 `filter` 过滤对象，以及包含 `limit` 数量上限与不透明 `cursor` 游标字符串的可选 `page` 对象。
- **字段投影 (Projection)**：列表与获取操作支持可选的 `projection.fields` 字段数组，以过滤返回属性。

## 有界地址扫描

按地址排序的扫描操作以协作方式检查内存项。
适用的列表查询操作包括：
- `code_unit.list`
- `data_unit.list`
- `instruction.list`
- `function.list`
- `global_variable.list`
- `symbol.list`
- `comment.list`
- `flow_override.list`

扫描操作接受 `scan` 对象。
`scan.range` 对象指定 `start` 和 `end` 地址。
`scan.timeout_ms` 超时限制在 100 至 60000 毫秒之间。
默认超时时间为 1000 毫秒。

响应结果中包含 `scan` 扫描元数据块：

```json
{
  "items": [],
  "next_cursor": "eyJ...",
  "scan": {
    "kind": "address",
    "requested_start": "ram:00100000",
    "requested_end": "ram:001fffff",
    "scanned_start": "ram:00100000",
    "scanned_end": "ram:0017ffff",
    "complete": false,
    "stop_reason": "timeout",
    "elapsed_ms": 1000
  }
}
```

`stop_reason` 属性报告 `completed`（完成）、`limit`（达上限）或 `timeout`（超时）。
即使匹配结果为 0，未完成的扫描仍会返回 `next_cursor`。
调用方将该值作为 `page.cursor` 传递，即可从上次扫描终止的位置继续扫描。

## 全局变量与数据协调

`global_variable` 系列方法统一协调顶层定义数据与其主标签。
创建或更新全局变量需要提供地址、名称与结构化数据类型引用。
变更操作绝不会覆盖指令或无关的已定义数据。
删除全局变量会清除数据定义，但默认保留其符号标签。

## 后续阅读

- 查阅[体系架构指南](architecture.md)了解模块划分。
- 阅读[协议规范](protocol.md)掌握信封格式与错误定义。
- 查阅[批处理与事务](batch-and-transactions.md)了解原子执行机制。
- 查阅[方法参考](../api.md)获取 53 个方法的完整列表。
