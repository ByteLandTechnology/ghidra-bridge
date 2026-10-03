# 体系架构 (Architecture)

Ghidra Bridge 采用单向严格依赖的模块化架构。
全部源码模块均位于 `modules/` 目录下。

## 依赖关系图

```text
modules/domain (领域服务接口与数据模型)
       ▲
       └── modules/wire (方法注册表与 JSON 编解码器)
                 ▲
                 └── modules/runtime (请求分发与会话控制)
                           ▲
                           ├── modules/transport/websocket (WebSocket JSON-RPC)
                           ├── modules/transport/mcp (MCP Streamable HTTP)
                           └── modules/adapter (Ghidra 服务实现)
                                     ▲
                                     └── modules/launcher (启动引导与脚本生成)
```

适配器模块还直接依赖 `modules/domain` 与 `modules/wire`。
启动器模块依赖适配器模块及两个传输模块。

该架构确保了领域逻辑、网络通信协议与 Ghidra 原生 API 之间的清晰解耦。

## 模块职责划分

### 1. `modules/domain`

领域模块定义核心服务接口与数据传输模型：
- 服务接口包括 `ProgramService`、`MemoryService`、`ListingService`、`FunctionService` 及 `DataTypeService` 等。
- 模型记录包括 `AddressResource`、`InstructionResource`、`FunctionResource` 以及 `Page` 分页模型。
- 定义领域异常，如 `DomainException` 与 `GlobalVariableConflictException`。
- **架构约束**：该模块严禁引入任何 Ghidra 专有 API 类。

### 2. `modules/wire`

通信协议模块维护统一的方法元数据目录：
- `ApiRegistry` 统一注册全部 53 个点分方法及其请求/响应 Schema。
- 通过 `JsonParser`、`JsonWriter` 与 `JsonUtil` 提供轻量级 JSON 解析与格式化工具。
- `ApiContractGenerator` 负责输出 `docs/api.md`、`docs/asyncapi.yaml` 及 `docs/mcp-tools.json`。
- **架构约束**：无类型的原始 JSON 数据在此边界完全终结。

### 3. `modules/runtime`

运行时模块管理请求调度与会话生命周期：
- `AgentDispatcher` 将入站请求分发至目标方法处理器。
- 每次只执行一个请求。`DispatchBarrier` 跟踪进行中的请求，并在停机期间拒绝新请求。
- 维护会话状态并协调安全平滑停机。
- **架构约束**：该模块不依赖任何 Ghidra 类。

### 4. `modules/adapter`

适配器模块负责将领域服务接口连接至 Ghidra 原生实现：
- `GhidraSession` 管理活跃程序引用与事务生命周期。
- 具体的服务实现类负责将领域操作转换为 Ghidra 专有 API 调用。
- `GhidraServiceFactory` 作为全量服务实现的装配工厂。
- **架构约束**：除启动器外，对 Ghidra 类的引用仅限该模块内部。

### 5. `modules/transport/websocket`

该模块实现 WebSocket 传输通道：
- `AgentWebSocketServer` 实现内嵌式 WebSocket 服务端。
- `AgentClient` 以内嵌服务端或连接 `ws_url` 的出站客户端方式运行 WebSocket 传输。
- `MessageEnvelope` 负责校验 JSON-RPC 2.0 请求、响应及错误信封。

### 6. `modules/transport/mcp`

该模块实现 Model Context Protocol 传输通道：
- `McpHttpServer` 实现符合 `2026-07-28` 规范的 Streamable HTTP 服务。
- `McpToolRegistry` 将 52 个点分方法投影为 14 个领域工具及 `ghidra.help`，不发布 `interface.get`。
- 在 `ghidra-bridge://contracts/mcp-tools` 提供静态工具契约资源。

### 7. `modules/launcher`

启动器模块负责运行时引导与 Ghidra 脚本打包：
- `Bootstrap` 读取启动参数并拉起所选的网络传输通道。
- 构建系统根据 `GhidraLauncher.java.template` 生成 `Bridge.java` 与 `GhidraMcp.java`。
- 打包编译产物并输出独立的 `ghidra-bridge.jar`。
- 出站模式下，连接关闭（包括宿主进程已停止）时会话结束。随后桥接取消正在运行的分析、保存程序，脚本返回，headless Ghidra 随之退出。宿主可通过 `exit_deadline_sec` 让 `GracefulExit` 在会话结束后的这段时间内 Ghidra 仍未退出时强制停止 JVM。到期时正在进行的保存会先完成。宿主不需要另外的看门狗进程。

## 架构边界检验

本项目通过自动化工具机械化校验架构边界：
- Gradle `verifyArchitecture` 任务扫描并验证所有模块的包引用规则。
- 仅 `modules/adapter` 与 `modules/launcher` 允许引入 `ghidra.` 前缀的类库。
- `verifyApiContracts` 任务在临时沙箱中重新生成契约，发现任何偏移即阻断构建。
- 执行 `./gradlew clean verify` 可执行完整的合规性验证。
