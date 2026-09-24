# Ghidra Bridge

[English](README.md) | [中文](README.zh-CN.md) | [日本語](README.ja-JP.md)

Ghidra Bridge 为正在运行的 Ghidra 程序提供网络访问接口。
运行时基于 Java 21 开发，支持 Ghidra 12.1。
它提供两种传输通道：WebSocket JSON-RPC 2.0 与 MCP Streamable HTTP `2026-07-28`。
运行时 JAR 包不包含任何第三方依赖。

## 主要特性

- **双传输通道**：支持通过 WebSocket JSON-RPC 2.0 或 MCP Streamable HTTP 访问 Ghidra。
- **统一方法目录**：一个类型严格的注册表定义 53 个点分方法。WebSocket 暴露全部 53 个；MCP 暴露其中 52 个，`interface.get` 仅限 WebSocket。
- **有界地址扫描**：按地址排序的列表查询支持协作超时取消与游标分页。
- **原子事务控制**：支持批量操作，并在遇到错误时自动进行事务回滚。
- **Headless 命令行模式**：支持在 Ghidra 无头模式脚本中运行，无需图形界面。

## 构建脚本

将 `GHIDRA_INSTALL_DIR` 环境变量设置为您的 Ghidra 安装目录。
然后使用 Gradle Wrapper 构建脚本：

```bash
./gradlew buildGhidraScript
```

构建任务会在 `build/ghidra-script/` 目录下生成三个文件：

```text
Bridge.java
GhidraMcp.java
ghidra-bridge.jar
```

请将这三个文件保存在同一目录下。
脚本加载器会根据相对路径自动定位 `ghidra-bridge.jar`。

## 启动桥接服务

### 在 Ghidra 图形界面中运行

1. 在 Ghidra CodeBrowser 中打开目标二进制程序。
2. 打开 Script Manager（脚本管理器）窗口。
3. 将 `build/ghidra-script/` 目录添加到脚本目录列表中。
4. 运行 `Bridge.java`（WebSocket）或 `GhidraMcp.java`（MCP）。
5. 在弹出的参数窗口中输入配置参数。

### 在 Ghidra Headless 无头模式中运行

您可以将 `GhidraMcp.java` 或 `Bridge.java` 作为后置脚本在无头模式中运行。
创建项目目录，然后导入并分析目标二进制文件。
请勿使用带点前缀的目录名（例如 `.cache`）作为项目路径。

```bash
mkdir -p /path/to/projects
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects demo \
  -import /path/to/target_binary \
  -scriptPath "$PWD/build/ghidra-script" \
  -postScript GhidraMcp.java host=127.0.0.1 port=8766 path=/mcp session_id=demo
```

该脚本将持续运行并处理请求，直到您停止该进程。
若要重新打开已有项目文件而跳过重复分析，请使用 `-process` 与 `-noanalysis`：

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects demo \
  -process target_binary -noanalysis \
  -scriptPath "$PWD/build/ghidra-script" \
  -postScript GhidraMcp.java host=127.0.0.1 port=8766 path=/mcp session_id=demo
```

## 配置参数

请使用严格的 `key=value` 键值对配置桥接服务。
启动器将拒绝未知参数、重复参数和驼峰命名的键。

```text
# 内嵌 WebSocket 服务端
host=127.0.0.1 port=8765 path=/ws/agent session_id=demo

# 主动出站 WebSocket 客户端
ws_url=ws://127.0.0.1:8765/ws/agent session_id=demo token=secret

# MCP HTTP 服务端
host=127.0.0.1 port=8766 path=/mcp session_id=demo token=secret
```

### 参数参考表

| 参数名 | 默认值 | 说明 |
|---|---|---|
| `host` | `127.0.0.1` | 服务端监听的本地网络接口地址。 |
| `port` | `8765` (WS) / `8766` (MCP) | HTTP 或 WebSocket 服务的 TCP 端口号。WebSocket 仅在未设置 `ws_url` 时使用默认值。 |
| `path` | `/ws/agent` (WS) / `/mcp` (MCP) | 请求分发所使用的 URL 路径端点。 |
| `session_id` | 程序名 | 当前活跃会话的唯一标识字符串。 |
| `token` | *(无)* | Bearer 认证所需的共享密钥 Token。 |
| `ws_url` | *(无)* | 作为出站客户端连接时的远程 WebSocket URL。 |
| `jar` | *(自动)* | 当 `ghidra-bridge.jar` 移离脚本所在目录时指定的实际路径。 |

## 安全规范

桥接服务强制执行严格的安全边界：

- **默认回环**：监听服务默认绑定至 `127.0.0.1`。
- **强制 Token**：绑定至非回环网卡的监听器必须配置 `token`。
- **Bearer 请求头**：入站请求必须携带 `Authorization: Bearer <token>` 头部。
- **拒绝 URL Token**：服务端直接以 HTTP 400 拒绝在 URL 查询参数中传递 Token。
- **日志脱敏**：安全 Token 绝不会被写入任何日志文件或输出控制台。

## API 与传输协议

公共 API 包含 53 个严格的点分方法，从 `interface.get` 到 `batch.execute`。

### WebSocket JSON-RPC 2.0

WebSocket 采用标准的 JSON-RPC 2.0 格式进行请求交互：

```json
{"jsonrpc":"2.0","id":"r1","method":"program.get","params":{}}
```

调用 `interface.get` 可发现所有受支持的方法及其输入输出 Schema。

### Model Context Protocol (MCP)

MCP 通过 Streamable HTTP 协议将除 `interface.get` 以外的相同操作映射为 15 个工具：
- `ghidra.help`：发现领域、列出操作或查看操作 Schema。
- 14 个领域工具：`ghidra.program`、`ghidra.memory`、`ghidra.function`、`ghidra.listing` 等。

调用操作时传递其在领域工具内的操作名及参数。
例如，`program.get` 方法对应 `ghidra.program` 的 `get` 操作：

```json
{
  "name": "ghidra.program",
  "arguments": {
    "operation": "get",
    "params": {}
  }
}
```

每个 MCP 请求还必须携带 MCP 元数据与头部，详见[协议规范](docs/zh/protocol.md)。

完整的 MCP 工具 Schema 亦可通过资源 `ghidra-bridge://contracts/mcp-tools` 获取。

## 文档索引

- [系统概述 (Overview)](docs/zh/overview.md)：系统架构理念、并发模型与查询规范。
- [体系架构 (Architecture)](docs/zh/architecture.md)：模块边界划分与依赖图解。
- [协议规范 (Protocol)](docs/zh/protocol.md)：JSON-RPC 信封、MCP 端点与错误响应格式。
- [批处理与事务 (Batch and Transactions)](docs/zh/batch-and-transactions.md)：原子批处理与事务边界机制。
- [开发指南 (Development)](docs/zh/development.md)：开发环境配置、工作流与质量门禁。
- [方法参考 (Method Reference)](docs/api.md)：全量 53 个方法的详细目录与 Schema。
- [AsyncAPI 契约 (AsyncAPI)](docs/asyncapi.yaml)：WebSocket 形式化契约。
- [MCP 工具契约 (MCP Tools)](docs/mcp-tools.json)：MCP 工具形式化定义。

## 验证构建

提交代码前请运行完整的质量验证套件：

```bash
./gradlew --no-daemon clean verify
```

`verify` 任务将严格检查：
- 架构隔离规则检查。
- 生成的 API 契约无任何偏移漂移。
- 生成脚本的构建与编译。

[tests/](tests/README.md) 中的 MCP 测试套件在 Ghidra Headless 模式下测试全部 MCP 工具。
