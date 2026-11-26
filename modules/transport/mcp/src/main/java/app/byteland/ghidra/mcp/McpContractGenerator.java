package app.byteland.ghidra.mcp;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiRegistry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public final class McpContractGenerator {
  private static final Set<String> FORBIDDEN_SCHEMA_KEYS =
      Set.of("oneOf", "anyOf", "allOf", "$ref", "$defs");
  private static final List<String> GUIDE_PATHS =
      List.of(
          "README.md",
          "README.zh-CN.md",
          "README.ja-JP.md",
          "docs/protocol.md",
          "docs/zh/protocol.md",
          "docs/ja/protocol.md",
          "docs/architecture.md",
          "docs/zh/architecture.md",
          "docs/ja/architecture.md");
  private static final Pattern DOTTED_MCP_TOOL_PATTERN =
      Pattern.compile(
          "(?<![A-Za-z0-9_])(?:ghidra|sample|other|<prefix>)\\."
              + "(?:help|bridge|program|address|memory|listing|global_variable|function|analysis"
              + "|decompilation|symbol|reference|comment|data_type|batch|<domain>)"
              + "(?![A-Za-z0-9_.])");
  private static final List<Pattern> STALE_MCP_SSE_PATTERNS =
      List.of(
          Pattern.compile("\\*\\*GET\\*\\*\\s*[:：].*\\b405\\b"),
          Pattern.compile("Allow:\\s*POST,\\s*OPTIONS(?!\\s*,)"),
          Pattern.compile("does not send server-sent events"),
          Pattern.compile("prefix and a dot"),
          Pattern.compile("不发送服务端推送事件"),
          Pattern.compile("サーバー送信イベント\\s*\\(SSE\\)\\s*も送信しません"));

  private McpContractGenerator() {}

  public static void main(String[] args) throws IOException {
    if (args.length >= 2 && "--verify".equals(args[0])) {
      verifyRepository(Path.of(args[1]).toAbsolutePath().normalize());
      return;
    }
    Path root = Path.of(args.length == 0 ? "." : args[0]).toAbsolutePath().normalize();
    Path output = root.resolve("docs/mcp-tools.json");
    List<Map<String, Object>> tools = new McpToolRegistry(ApiRegistry.catalog()).listTools();
    validateTools(tools, McpConfig.DEFAULT_TOOL_PREFIX);
    Files.createDirectories(output.getParent());
    Files.writeString(
        output,
        JsonUtil.toJson(
                JsonUtil.canonical(
                    Map.of(
                        "version",
                        ApiRegistry.INTERFACE_VERSION,
                        "protocol_version",
                        "2026-07-28",
                        "tools",
                        tools)))
            + "\n",
        StandardCharsets.UTF_8);
  }

  @SuppressWarnings("unchecked")
  static void verifyRepository(Path root) throws IOException {
    Path contractPath = root.resolve("docs/mcp-tools.json");
    if (!Files.isRegularFile(contractPath)) {
      throw new IllegalStateException("Missing MCP contract file: " + contractPath);
    }
    Object parsed = JsonUtil.parse(Files.readString(contractPath, StandardCharsets.UTF_8));
    if (!(parsed instanceof Map<?, ?> contract)
        || !(contract.get("tools") instanceof List<?> rawTools)) {
      throw new IllegalStateException("Invalid docs/mcp-tools.json root object");
    }
    List<Map<String, Object>> tools = new ArrayList<>(rawTools.size());
    for (Object item : rawTools) {
      if (!(item instanceof Map<?, ?> map)) {
        throw new IllegalStateException("Tool entry in docs/mcp-tools.json must be an object");
      }
      tools.add((Map<String, Object>) map);
    }
    validateTools(tools, McpConfig.DEFAULT_TOOL_PREFIX);

    for (String relative : GUIDE_PATHS) {
      Path guide = root.resolve(relative);
      if (!Files.isRegularFile(guide)) {
        throw new IllegalStateException("Missing guide file: " + relative);
      }
      verifyTextFile(guide, relative);
    }

    Path mcpSources = root.resolve("modules/transport/mcp/src/main/java");
    if (Files.isDirectory(mcpSources)) {
      try (Stream<Path> paths = Files.walk(mcpSources)) {
        for (Path javaFile : paths.filter(path -> path.toString().endsWith(".java")).toList()) {
          if (javaFile.getFileName().toString().equals("McpContractGenerator.java")) {
            continue;
          }
          verifyJavaComments(javaFile, root.relativize(javaFile).toString());
        }
      }
    }
  }

  private static void verifyTextFile(Path file, String label) throws IOException {
    List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
    for (int index = 0; index < lines.size(); index++) {
      checkLine(lines.get(index), label, index + 1);
    }
  }

  private static void verifyJavaComments(Path file, String label) throws IOException {
    List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
    boolean inBlockComment = false;
    for (int index = 0; index < lines.size(); index++) {
      String trimmed = lines.get(index).trim();
      if (trimmed.startsWith("/*")) {
        inBlockComment = true;
      }
      if (inBlockComment || trimmed.startsWith("//")) {
        checkLine(trimmed, label, index + 1);
      }
      if (inBlockComment && trimmed.contains("*/")) {
        inBlockComment = false;
      }
    }
  }

  private static void checkLine(String line, String label, int lineNumber) {
    if (DOTTED_MCP_TOOL_PATTERN.matcher(line).find()) {
      throw new IllegalStateException(
          "Dotted MCP tool name in " + label + ":" + lineNumber + ": " + line.trim());
    }
    for (Pattern stalePattern : STALE_MCP_SSE_PATTERNS) {
      if (stalePattern.matcher(line).find()) {
        throw new IllegalStateException(
            "Stale MCP documentation in " + label + ":" + lineNumber + ": " + line.trim());
      }
    }
  }

  static void validateTools(List<Map<String, Object>> tools, String expectedPrefix) {
    if (tools.size() != 15) {
      throw new IllegalStateException("Expected 15 MCP tools, got " + tools.size());
    }
    String requiredPrefix = expectedPrefix + "_";
    String helpToolName = requiredPrefix + "help";
    String listingToolName = requiredPrefix + "listing";
    for (Map<String, Object> tool : tools) {
      if (!(tool.get("name") instanceof String name)) {
        throw new IllegalStateException("Tool name must be a string");
      }
      if (name.contains(".") || !name.startsWith(requiredPrefix)) {
        throw new IllegalStateException(
            "MCP tool name must use underscore prefix " + requiredPrefix + ": " + name);
      }
      if (listingToolName.equals(name)
          && (!(tool.get("description") instanceof String description)
              || !description.contains("data units"))) {
        throw new IllegalStateException(
            "Listing tool description must mention data units: " + name);
      }
      if (!(tool.get("inputSchema") instanceof Map<?, ?> inputSchema)) {
        throw new IllegalStateException("Missing inputSchema on tool " + name);
      }
      if (!Boolean.FALSE.equals(inputSchema.get("additionalProperties"))) {
        throw new IllegalStateException(
            "Tool inputSchema must set additionalProperties=false: " + name);
      }
      rejectForbiddenSchemaKeys(name, inputSchema);
      if (helpToolName.equals(name)) {
        continue;
      }
      if (!(inputSchema.get("properties") instanceof Map<?, ?> props)
          || !(props.get("params") instanceof Map<?, ?> params)) {
        throw new IllegalStateException("Missing params schema on domain tool " + name);
      }
      if (!Boolean.FALSE.equals(params.get("additionalProperties"))) {
        throw new IllegalStateException(
            "Domain params schema must set additionalProperties=false: " + name);
      }
      if (!(params.get("properties") instanceof Map<?, ?> paramProperties)
          || paramProperties.isEmpty()) {
        throw new IllegalStateException("Domain tool params.properties must not be empty: " + name);
      }
    }
  }

  private static void rejectForbiddenSchemaKeys(String toolName, Object node) {
    if (node instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        String key = String.valueOf(entry.getKey());
        if (FORBIDDEN_SCHEMA_KEYS.contains(key)) {
          throw new IllegalStateException(
              "Forbidden schema keyword " + key + " in MCP tool " + toolName);
        }
        rejectForbiddenSchemaKeys(toolName, entry.getValue());
      }
    } else if (node instanceof List<?> list) {
      for (Object item : list) {
        rejectForbiddenSchemaKeys(toolName, item);
      }
    }
  }
}
