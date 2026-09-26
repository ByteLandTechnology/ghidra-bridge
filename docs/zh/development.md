# 开发指南 (Development Guide)

本指南说明如何构建、扩展与验证 Ghidra Bridge 代码库。

## 环境准备

- **JDK 开发包**：必须安装 Java 21 (JDK 21)。
- **Ghidra 逆向分析工具**：编译适配器与运行 MCP 测试需要 Ghidra 12.1 或更新版本。
- **环境变量**：将 `GHIDRA_INSTALL_DIR` 设置为 Ghidra 的本地安装路径。

Gradle 按以下优先级解析 Ghidra 安装路径：
1. 命令行参数 `-PghidraInstallDir`。
2. 环境变量 `GHIDRA_INSTALL_DIR`。
3. 系统 `PATH` 中的 `ghidraRun` 可执行文件。
4. Homebrew 安装的 Ghidra。
5. 系统 `PATH` 中的 `analyzeHeadless` 可执行文件。
6. 本地机器上的标准安装目录。

## Gradle 常用工作流

请始终使用仓库内建的 Gradle Wrapper：

```bash
# 构建用于分发的脚本与 JAR 包
./gradlew buildGhidraScript

# 运行全量质量检查
./gradlew --no-daemon clean verify
```

`buildGhidraScript` 任务在 `build/ghidra-script/` 目录下生成三个文件：
- `Bridge.java`
- `GhidraMcp.java`
- `ghidra-bridge.jar`

## 如何新增或修改 API 操作

修改公共接口请严格按照以下步骤进行：

### 第一步：更新领域模型

在 `modules/domain` 中定义服务接口与数据传输类型。
保持领域接口与 Ghidra API 完全解耦，严禁引入 Ghidra 原生类型。

### 第二步：实现 Ghidra 适配器

在 `modules/adapter` 中实现新增的领域服务方法。
将 Ghidra 原生数据结构转换为强类型的领域记录。
对于修改操作，使用 `GhidraSession` 统一管理底层事务。

### 第三步：在 Wire 模块注册方法

在 `modules/wire` 中通过 `ApiRegistry` 注册新操作：
- 分配点分公共方法名（如 `program.get`）。
- 定义输入参数与返回结果的 Schema。
- 将分发处理器关联至领域服务接口。

### 第四步：重新生成公共契约文件

执行契约生成任务：

```bash
./gradlew generateApiContracts
```

该任务将自动重新生成：
- `docs/api.md`
- `docs/asyncapi.yaml`
- `docs/mcp-tools.json`

请勿手动修改上述生成的文件。
若提交的文件与生成器输出存在差异，构建校验将会失败。

## 质量门禁

在提交代码更改之前，必须运行全量验证套件：

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

验证套件执行以下检查：
- **架构隔离**：`verifyArchitecture` 确保仅 adapter 和 launcher 允许导入 Ghidra 类。
- **契约一致性**：`verifyApiContracts` 确保文档契约与代码完全一致。
- **生成脚本测试**：`compileGeneratedScripts` 确保生成的启动脚本编译通过。
- **分发产物**：`verifyDistribution` 校验 `build/ghidra-script/` 的内容。

## MCP 测试

`tests/` 目录包含 MCP 测试套件。
它在 Ghidra Headless 模式下，针对 C/C++ 示例二进制测试全部 MCP 工具。
运行方法见 [tests/README.md](../../tests/README.md)。

## 版本发布

CI 工作流使用 semantic-release 自动发布版本。
只有推送到 `main` 且 `verify` 任务通过后，才会开始发布。

semantic-release 读取上一个 `v*` 标签之后的 Conventional Commit 提交消息：
- `fix`：发布补丁版本，例如 `0.3.1`。
- `feat`：发布次版本，例如 `0.4.0`。
- 类型后带 `!` 或包含 `BREAKING CHANGE:` 脚注：发布主版本。
- 其他类型（例如 `docs`、`ci`、`test`）：不发布版本。

每次发布都会创建 `v<版本号>` 标签，以及附带自动生成说明的 GitHub Release。
Release 包含两个附件：
- `ghidra-bridge-<版本号>.zip`：包含 `Bridge.java`、`GhidraMcp.java`、`ghidra-bridge.jar`、`LICENSE` 与 `README.md`。
- `ghidra-bridge-<版本号>.zip.sha256`：压缩包的 SHA-256 校验和。

发布过程不会向仓库提交文件。
构建从 Gradle 属性 `releaseVersion` 获取版本号，本地构建使用版本号 `0.0.0-dev`。

在本地构建发布压缩包：

```bash
bash .github/scripts/package-release.sh 0.3.0
```

在不发布的情况下预览下一个版本号：

```bash
npm ci
npx semantic-release --dry-run --no-ci
```
