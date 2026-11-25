package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiRegistry;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class McpToolRegistryTest {
  private static final List<String> UNSUPPORTED_SCHEMA_KEYS =
      List.of("oneOf", "anyOf", "allOf", "$ref", "$defs", "additionalProperties");

  @Test
  @DisplayName("Publishes 56 provider-safe underscored tools with exact required sets and hints")
  void publishesProviderSafePerOperationTools() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    List<Map<String, Object>> tools = registry.listTools();

    assertEquals(56, tools.size());
    assertEquals("ghidra_help", tools.get(0).get("name"));

    Set<String> seenNames = new HashSet<>();
    int readOnlyOperations = 0;
    for (int index = 0; index < tools.size(); index++) {
      Map<String, Object> tool = tools.get(index);
      String name = (String) tool.get("name");
      assertTrue(seenNames.add(name), "duplicate tool name: " + name);
      assertTrue(name.length() <= 64, "tool name exceeds 64 chars: " + name);
      assertTrue(name.matches("[A-Za-z_][A-Za-z0-9_]*"), "invalid tool name: " + name);

      @SuppressWarnings("unchecked")
      Map<String, Object> schema = (Map<String, Object>) tool.get("inputSchema");
      assertEquals("object", schema.get("type"), name + " inputSchema.type");
      assertTrue(schema.get("properties") instanceof Map<?, ?>, name + " inputSchema.properties");
      assertNoUnsupportedSchemaKeys(name, schema);
      assertNull(tool.get("outputSchema"), name + " must not expose outputSchema in tools/list");

      @SuppressWarnings("unchecked")
      Map<String, Object> annotations = (Map<String, Object>) tool.get("annotations");
      assertEquals(Boolean.FALSE, annotations.get("openWorldHint"), name + " openWorldHint");
      if (index > 0 && Boolean.TRUE.equals(annotations.get("readOnlyHint"))) {
        readOnlyOperations++;
        assertEquals(
            Boolean.FALSE, annotations.get("destructiveHint"), name + " readOnly destructiveHint");
      }
    }
    assertEquals(28, readOnlyOperations);

    Map<String, Object> decompilationGet = findTool(tools, "ghidra_decompilation_get");
    assertEquals(List.of("selector"), inputSchema(decompilationGet).get("required"));
    assertEquals(Boolean.TRUE, annotations(decompilationGet).get("readOnlyHint"));
    assertEquals(Boolean.FALSE, annotations(decompilationGet).get("destructiveHint"));

    Map<String, Object> referenceList = findTool(tools, "ghidra_reference_list");
    assertEquals(List.of("filter"), inputSchema(referenceList).get("required"));
    assertEquals(Boolean.TRUE, annotations(referenceList).get("readOnlyHint"));
    assertEquals(Boolean.FALSE, annotations(referenceList).get("destructiveHint"));

    for (String additiveTool :
        List.of(
            "ghidra_function_create",
            "ghidra_comment_create",
            "ghidra_data_type_create",
            "ghidra_global_variable_create",
            "ghidra_function_parameter_create")) {
      Map<String, Object> createTool = findTool(tools, additiveTool);
      assertEquals(Boolean.FALSE, annotations(createTool).get("readOnlyHint"), additiveTool);
      assertEquals(Boolean.FALSE, annotations(createTool).get("destructiveHint"), additiveTool);
    }

    Map<String, Object> localVarPatch = findTool(tools, "ghidra_function_local_variable_patch");
    assertEquals(List.of("selector", "patch"), inputSchema(localVarPatch).get("required"));
    assertEquals(Boolean.TRUE, annotations(localVarPatch).get("destructiveHint"));

    Map<String, Object> batchExecute = findTool(tools, "ghidra_batch_execute");
    assertEquals(List.of("items"), inputSchema(batchExecute).get("required"));
    assertEquals(Boolean.TRUE, annotations(batchExecute).get("destructiveHint"));

    String maxPrefix = "a" + "b".repeat(33);
    McpToolRegistry maxPrefixRegistry = new McpToolRegistry(ApiRegistry.catalog(), maxPrefix);
    for (Map<String, Object> tool : maxPrefixRegistry.listTools()) {
      String name = (String) tool.get("name");
      assertTrue(name.length() <= 64, "34-char prefix produced >64 char name: " + name);
    }
  }

  @Test
  @DisplayName("Resolves flat tools, legacy domain tools, and rich ghidra_help operation schemas")
  void resolvesFlatAndLegacyToolsAndHelpSchemas() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());

    assertTrue(registry.hasTool("ghidra_help"));
    assertTrue(registry.hasTool("ghidra.help"));
    assertTrue(registry.hasTool("ghidra_function_local_variable_patch"));
    assertTrue(registry.hasTool("ghidra_function"));
    assertTrue(registry.hasTool("ghidra.function"));
    assertFalse(registry.hasTool("ghidra_unknown"));

    McpToolRegistry.OperationTarget flatTarget =
        registry.findOperationTool("ghidra_function_local_variable_patch");
    assertNotNull(flatTarget);
    assertEquals("function", flatTarget.domain());
    assertEquals("local_variable.patch", flatTarget.operation());
    assertEquals("function_local_variable.patch", flatTarget.descriptor().name());
    assertEquals(
        "function_local_variable.patch",
        registry.findTool("ghidra_function", "local_variable.patch").name());
    assertEquals(
        "function_local_variable.patch",
        registry.findTool("ghidra.function", "local_variable.patch").name());

    Map<String, Object> domainHelp = registry.help(Map.of("domain", "memory"));
    assertEquals("ghidra_memory", domainHelp.get("domain"));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> operations = (List<Map<String, Object>>) domainHelp.get("operations");
    assertFalse(operations.isEmpty());
    Map<String, Object> blockList =
        operations.stream()
            .filter(entry -> "block.list".equals(entry.get("name")))
            .findFirst()
            .orElseThrow();
    assertEquals("ghidra_memory_block_list", blockList.get("tool"));
    assertEquals("memory_block.list", blockList.get("method"));
    assertTrue(blockList.get("description") instanceof String);
    assertTrue(blockList.get("effects") instanceof Map<?, ?>);
    assertTrue(blockList.get("inputSchema") instanceof Map<?, ?>);
    assertTrue(blockList.get("outputSchema") instanceof Map<?, ?>);
  }

  private static void assertNoUnsupportedSchemaKeys(String toolName, Object value) {
    if (value instanceof Map<?, ?> map) {
      for (String key : UNSUPPORTED_SCHEMA_KEYS) {
        assertFalse(map.containsKey(key), toolName + " contains unsupported key " + key);
      }
      for (Object child : map.values()) {
        assertNoUnsupportedSchemaKeys(toolName, child);
      }
    } else if (value instanceof List<?> list) {
      for (Object item : list) {
        assertNoUnsupportedSchemaKeys(toolName, item);
      }
    }
  }

  private static Map<String, Object> findTool(List<Map<String, Object>> tools, String name) {
    return tools.stream()
        .filter(tool -> name.equals(tool.get("name")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("missing tool: " + name));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> inputSchema(Map<String, Object> tool) {
    return (Map<String, Object>) tool.get("inputSchema");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> annotations(Map<String, Object> tool) {
    return (Map<String, Object>) tool.get("annotations");
  }
}
