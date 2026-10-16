# 开发指南 (Development Guide)

本指南说明如何构建、扩展与验证 Ghidra Bridge 代码库。

## 环境准备

- **JDK 开发包**：必须安装 Java 21 (JDK 21)。
- **Ghidra 逆向分析工具**：编译适配器需要 Ghidra 12.1 或更新版本。
- **环境变量**：将 `GHIDRA_INSTALL_DIR` 设置为 Ghidra 的本地安装路径。

Gradle 按以下优先级解析 Ghidra 安装路径：
1. 命令行参数 `-PghidraInstallDir`。
2. 环境变量 `GHIDRA_INSTALL_DIR`。
3. 系统 `PATH` 中的 `ghidraRun` 可执行文件。
4. Homebrew 安装的 Ghidra。
5. 系统 `PATH` 中的 `analyzeHeadless` 可执行文件。
6. 本地机器上的标准安装目录。

## 使用 Gradle

请始终使用此仓库中的 Gradle Wrapper：

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

请勿直接修改上述生成的文件。
若仓库文件与生成器输出存在差异，构建校验将会失败。

## 质量检查

在提交代码更改之前，必须运行全量验证套件：

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

验证套件执行以下检查：
- **架构隔离**：`verifyArchitecture` 确保仅 adapter 和 launcher 允许导入 Ghidra 类。
- **契约一致性**：`verifyApiContracts` 确保文档契约与代码完全一致。
- **生成脚本编译**：`compileGeneratedScripts` 确保生成的启动脚本编译通过。
- **分发产物**：`verifyDistribution` 校验 `build/ghidra-script/` 的内容。

## 版本发布

CI 工作流使用 release-please 管理版本和发布说明。
推送到 `main` 且 `verify` 任务通过后，release-please 会创建或更新发布拉取请求。
该拉取请求更新 `version.txt`、`.release-please-manifest.json` 和 `CHANGELOG.md`。
请在拉取请求中检查版本号和变更说明。
将该拉取请求合并到 `main` 以开始发布。
验证通过后，release-please 创建 `v<版本号>` 标签和 GitHub Release。

release-please 根据 Conventional Commit 提交消息计算版本号：

- `fix`：递增补丁版本，例如 `1.2.1`。
- `feat`：递增次版本，例如 `1.3.0`。
- 类型后带 `!` 或包含 `BREAKING CHANGE:` 脚注：递增主版本。
- 其他类型（例如 `docs`、`ci`、`test`）：不会单独触发版本发布。

`publish` 任务获取发布对应的提交并验证构建。
然后它上传两个附件：

- `ghidra-bridge-<版本号>.zip`：包含 `Bridge.java`、`GhidraMcp.java`、`ghidra-bridge.jar`、
  `LICENSE` 与 `README.md`。
- `ghidra-bridge-<版本号>.zip.sha256`：压缩包的 SHA-256 校验和。

Gradle 默认从 `version.txt` 读取版本号，`releaseVersion` 属性可以覆盖该值。
打包脚本会检查发布版本与 `version.txt` 和 JAR 清单中的版本一致。
在本地构建并验证发布压缩包：

```bash
bash .github/scripts/package-release.sh
```

在 Settings > Actions > General 中启用
“Allow GitHub Actions to create and approve pull requests”。
工作流默认使用 `GITHUB_TOKEN`，该令牌创建的拉取请求不会在没有新事件时启动 CI。
如需在发布拉取请求上运行 CI，设置仓库 secret `RELEASE_PLEASE_TOKEN`，使用个人访问令牌。
为该令牌授予此仓库的 Contents、Issues 和 Pull requests 写权限。
详见 [release-please Action 文档](https://github.com/googleapis/release-please-action)。

如果 `publish` 任务失败，可在 GitHub Actions 中选择 “Re-run failed jobs”。
上传步骤可以覆盖先前未完成尝试中的附件。
