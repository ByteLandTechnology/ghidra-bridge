package app.byteland.ghidra.mcp;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiRegistry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Generates the MCP tool catalog JSON file from {@link ApiRegistry}.
 */
public final class McpContractGenerator {
  private McpContractGenerator() {}

  /**
   * Writes {@code docs/mcp-tools.json} under the target root directory.
   *
   * @param args optional single root directory path
   * @throws IOException if the contract file write fails
   */
  public static void main(String[] args) throws IOException {
    Path root = Path.of(args.length == 0 ? "." : args[0]).toAbsolutePath().normalize();
    Path output = root.resolve("docs/mcp-tools.json");
    Files.createDirectories(output.getParent());
    Files.writeString(output,
        JsonUtil.toJson(JsonUtil.canonical(Map.of("version", ApiRegistry.INTERFACE_VERSION,
            "protocol_version", "2026-07-28",
            "tools", new McpToolRegistry(ApiRegistry.catalog()).listTools()))) + "\n",
        StandardCharsets.UTF_8);
  }
}
