package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpSearchCatalogTest {
  @Test
  @SuppressWarnings("unchecked")
  void preservesFifteenToolsAndExposesStringListAndMemoryFind() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    List<Map<String, Object>> tools = registry.listTools();
    assertEquals(15, tools.size());

    assertNotNull(registry.findTool("ghidra_listing", "string.list"));
    assertEquals("string.list", registry.findTool("ghidra_listing", "string.list").name());
    assertNotNull(registry.findTool("ghidra_memory", "find"));
    assertEquals("memory.find", registry.findTool("ghidra_memory", "find").name());

    Map<String, Object> listingOps = registry.help(Map.of("domain", "listing"));
    List<Map<String, Object>> operations =
        (List<Map<String, Object>>) listingOps.get("operations");
    assertTrue(
        operations.stream()
            .anyMatch(
                item ->
                    "string.list".equals(item.get("name"))
                        && "string.list".equals(item.get("method"))));

    Map<String, Object> stringHelp =
        registry.help(Map.of("domain", "ghidra_listing", "operation", "string.list"));
    assertEquals("string.list", stringHelp.get("method"));
    assertNotNull(stringHelp.get("inputSchema"));
    assertNotNull(stringHelp.get("outputSchema"));

    Map<String, Object> findHelp =
        registry.help(Map.of("domain", "ghidra_memory", "operation", "find"));
    assertEquals("memory.find", findHelp.get("method"));
    assertNotNull(findHelp.get("inputSchema"));
    assertNotNull(findHelp.get("outputSchema"));
  }
}
