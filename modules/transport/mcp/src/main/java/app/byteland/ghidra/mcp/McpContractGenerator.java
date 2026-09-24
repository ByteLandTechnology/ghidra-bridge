package app.byteland.ghidra.mcp;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiRegistry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.List;
import java.util.TreeMap;

public final class McpContractGenerator {
  private McpContractGenerator() {}

  public static void main(String[] args) throws IOException {
    Path root = Path.of(args.length == 0 ? "." : args[0]).toAbsolutePath().normalize();
    Path output = root.resolve("docs/mcp-tools.json");
    Files.createDirectories(output.getParent());
    Files.writeString(output,
        JsonUtil.toJson(canonical(Map.of("version", ApiRegistry.INTERFACE_VERSION,
            "protocol_version", "2026-07-28",
            "tools", new McpToolRegistry(ApiRegistry.catalog()).listTools()))) + "\n",
        StandardCharsets.UTF_8);
  }

  private static Object canonical(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      map.forEach((key, child) -> sorted.put(String.valueOf(key), canonical(child)));
      return sorted;
    }
    if (value instanceof List<?> list) return list.stream().map(McpContractGenerator::canonical).toList();
    return value;
  }
}
