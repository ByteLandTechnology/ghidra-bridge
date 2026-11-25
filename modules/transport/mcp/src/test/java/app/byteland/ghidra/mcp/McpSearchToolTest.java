package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpSearchToolTest {

  @Test
  @SuppressWarnings("unchecked")
  void exposesTopLevelGhidraSearchToolWithStringsAndBytesOperations() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    assertTrue(registry.hasTool("ghidra_search"));

    Map<String, Object> searchTool =
        registry.listTools().stream()
            .filter(tool -> "ghidra_search".equals(tool.get("name")))
            .findFirst()
            .orElse(null);
    assertNotNull(searchTool);

    Map<String, Object> inputSchema = (Map<String, Object>) searchTool.get("inputSchema");
    Map<String, Object> props = (Map<String, Object>) inputSchema.get("properties");
    Map<String, Object> operationProp = (Map<String, Object>) props.get("operation");
    assertEquals(List.of("strings", "bytes"), operationProp.get("enum"));

    Map<String, Object> domainHelp = registry.help(Map.of("domain", "ghidra_search"));
    assertEquals("ghidra_search", domainHelp.get("domain"));
    assertEquals(List.of("strings", "bytes"), domainHelp.get("operations"));

    Map<String, Object> stringsHelp =
        registry.help(Map.of("domain", "search", "operation", "strings"));
    assertEquals("search.strings", stringsHelp.get("method"));

    Map<String, Object> bytesHelp =
        registry.help(Map.of("domain", "search", "operation", "bytes"));
    assertEquals("search.bytes", bytesHelp.get("method"));
  }
}
