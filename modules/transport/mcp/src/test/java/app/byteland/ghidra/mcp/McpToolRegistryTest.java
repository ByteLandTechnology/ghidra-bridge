package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiRegistry;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class McpToolRegistryTest {
  private static final Pattern TOOL_NAME_PATTERN = Pattern.compile("[A-Za-z0-9_-]{1,64}");

  @Test
  void publishesOneTypedToolPerMethodWithAccurateAnnotations() {
    ApiCatalog catalog = ApiRegistry.catalog();
    McpToolRegistry registry = new McpToolRegistry(catalog);
    List<Map<String, Object>> tools = registry.listTools();

    assertEquals(56, tools.size());
    Map<String, Object> help = tools.get(0);
    assertEquals("ghidra_help", help.get("name"));
    assertEquals(
        Map.of(
            "readOnlyHint", true,
            "destructiveHint", false,
            "idempotentHint", true,
            "openWorldHint", false),
        help.get("annotations"));

    int readOnlyCount = 0;
    int nonDestructiveMutationCount = 0;
    int destructiveCount = 0;

    for (int i = 1; i < tools.size(); i++) {
      Map<String, Object> tool = tools.get(i);
      String name = String.valueOf(tool.get("name"));
      assertTrue(TOOL_NAME_PATTERN.matcher(name).matches(), name);
      assertFalse(name.contains("."), name);

      MethodDescriptor descriptor = registry.findOperationTool(name);
      assertNotNull(descriptor, name);
      assertEquals(descriptor.inputSchema(), tool.get("inputSchema"), name);
      assertEquals(descriptor.outputSchema(), tool.get("outputSchema"), name);
      assertEquals(descriptor.mcpTool().get("annotations"), tool.get("annotations"), name);

      Map<?, ?> inputSchema = (Map<?, ?>) tool.get("inputSchema");
      assertEquals("object", inputSchema.get("type"), name);
      assertFalse(inputSchema.containsKey("oneOf"), name);
      assertFalse(inputSchema.containsKey("anyOf"), name);
      assertNotNull(inputSchema.get("properties"), name);

      Map<?, ?> annotations = (Map<?, ?>) tool.get("annotations");
      boolean readOnlyHint = Boolean.TRUE.equals(annotations.get("readOnlyHint"));
      boolean destructiveHint = Boolean.TRUE.equals(annotations.get("destructiveHint"));
      if (readOnlyHint) {
        assertFalse(destructiveHint, name);
        readOnlyCount++;
      } else if (destructiveHint) {
        destructiveCount++;
      } else {
        nonDestructiveMutationCount++;
      }
    }

    assertEquals(28, readOnlyCount);
    assertEquals(8, nonDestructiveMutationCount);
    assertEquals(19, destructiveCount);

    assertNotNull(registry.findOperationTool("ghidra_decompilation_get"));
    assertNotNull(registry.findOperationTool("ghidra_reference_list"));
    assertNotNull(registry.findOperationTool("ghidra_function_list"));
    assertNotNull(registry.findOperationTool("ghidra_comment_create"));
    assertNotNull(registry.findOperationTool("ghidra_program_save"));
    assertNotNull(registry.findOperationTool("ghidra_memory_write"));
    assertNotNull(registry.findOperationTool("ghidra_function_local_variable_patch"));
    assertNull(registry.findOperationTool("ghidra_interface_get"));

    assertTrue(registry.hasTool("ghidra_help"));
    assertTrue(registry.hasTool("ghidra_memory_read"));
    assertTrue(registry.hasTool("ghidra_memory"));
    assertFalse(registry.hasTool("ghidra_unknown"));
    assertEquals("memory.read", registry.findTool("ghidra_memory", "read").name());
  }

  @Test
  void boundsToolPrefixLengthSoEveryToolNameFitsInSixtyFourCharacters() {
    String maxPrefix = "a".repeat(McpConfig.MAX_TOOL_PREFIX_LENGTH);
    assertEquals(maxPrefix, McpConfig.requireToolPrefix(maxPrefix));

    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog(), maxPrefix);
    for (Map<String, Object> tool : registry.listTools()) {
      String name = String.valueOf(tool.get("name"));
      assertTrue(name.length() <= McpConfig.MAX_TOOL_NAME_LENGTH, name);
      assertTrue(TOOL_NAME_PATTERN.matcher(name).matches(), name);
    }

    String tooLong = "a".repeat(McpConfig.MAX_TOOL_PREFIX_LENGTH + 1);
    assertThrows(IllegalArgumentException.class, () -> McpConfig.requireToolPrefix(tooLong));
    assertThrows(IllegalArgumentException.class, () -> McpConfig.requireToolPrefix("bad.prefix"));
  }

  @Test
  void helpReturnsDomainsOperationsAndSingleOperationMetadata() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    Map<String, Object> domains = registry.help(Map.of());
    List<?> domainList = (List<?>) domains.get("domains");
    assertEquals(14, domainList.size());
    assertTrue(domainList.contains("ghidra_memory"));

    Map<String, Object> operations = registry.help(Map.of("domain", "memory"));
    assertEquals("ghidra_memory", operations.get("domain"));
    assertEquals(List.of("block.get", "block.list", "read", "write"), operations.get("operations"));

    Map<String, Object> detail = registry.help(Map.of("domain", "ghidra_memory", "operation", "read"));
    assertEquals("ghidra_memory_read", detail.get("tool"));
    assertEquals("memory.read", detail.get("method"));
    assertNotNull(detail.get("inputSchema"));
    assertNotNull(detail.get("outputSchema"));
  }
}
