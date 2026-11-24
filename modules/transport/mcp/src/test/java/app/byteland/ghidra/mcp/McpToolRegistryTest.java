package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpToolRegistryTest {
  @Test
  void publishesListingAssemblyDisassemblyAndClearOperations() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    Map<String, Object> help = registry.help(Map.of("domain", "listing"));
    @SuppressWarnings("unchecked")
    List<String> operations = (List<String>) help.get("operations");
    assertTrue(operations.contains("code_unit.clear"));
    assertTrue(operations.contains("instruction.assemble"));
    assertTrue(operations.contains("instruction.disassemble"));

    assertNotNull(registry.findTool("ghidra_listing", "code_unit.clear"));
    assertNotNull(registry.findTool("ghidra_listing", "instruction.assemble"));
    assertNotNull(registry.findTool("ghidra_listing", "instruction.disassemble"));
    assertEquals(
        "instruction.assemble",
        registry.findTool("ghidra_listing", "instruction.assemble").name());
  }
}
