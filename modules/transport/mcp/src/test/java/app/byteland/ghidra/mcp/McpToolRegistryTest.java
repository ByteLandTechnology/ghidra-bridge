package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiRegistry;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class McpToolRegistryTest {

  private static final Set<String> FORBIDDEN_SCHEMA_KEYS =
      Set.of("oneOf", "anyOf", "allOf", "$ref", "$defs", "additionalProperties");

  @Test
  void splitsMixedDomainsAndComputesAccurateHints() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    List<Map<String, Object>> tools = registry.listTools();
    assertEquals(25, tools.size());
    assertEquals("ghidra_help", tools.getFirst().get("name"));

    Map<String, Map<String, Object>> byName = new LinkedHashMap<>();
    for (Map<String, Object> tool : tools) {
      String name = String.valueOf(tool.get("name"));
      assertTrue(name.length() <= McpConfig.MAX_TOOL_NAME_LENGTH, name);
      assertNoForbiddenSchemaKeys(name, tool.get("inputSchema"));
      byName.put(name, tool);
    }

    List<String> expectedReadTools =
        List.of(
            "ghidra_bridge",
            "ghidra_program",
            "ghidra_address",
            "ghidra_memory",
            "ghidra_listing",
            "ghidra_global_variable",
            "ghidra_function",
            "ghidra_analysis",
            "ghidra_decompilation",
            "ghidra_symbol",
            "ghidra_reference",
            "ghidra_comment",
            "ghidra_data_type");
    assertEquals(13, expectedReadTools.size());
    for (String readTool : expectedReadTools) {
      Map<String, Object> annotations = annotations(byName.get(readTool));
      assertEquals(Boolean.TRUE, annotations.get("readOnlyHint"), readTool);
      assertEquals(Boolean.FALSE, annotations.get("destructiveHint"), readTool);
      assertEquals(Boolean.TRUE, annotations.get("idempotentHint"), readTool);
      assertEquals(Boolean.FALSE, annotations.get("openWorldHint"), readTool);
    }

    List<String> nonDestructiveWrites = List.of("ghidra_program_write", "ghidra_analysis_write");
    for (String writeTool : nonDestructiveWrites) {
      Map<String, Object> annotations = annotations(byName.get(writeTool));
      assertEquals(Boolean.FALSE, annotations.get("readOnlyHint"), writeTool);
      assertEquals(Boolean.FALSE, annotations.get("destructiveHint"), writeTool);
    }

    List<String> destructiveWrites =
        List.of(
            "ghidra_bridge_write",
            "ghidra_memory_write",
            "ghidra_listing_write",
            "ghidra_global_variable_write",
            "ghidra_function_write",
            "ghidra_symbol_write",
            "ghidra_comment_write",
            "ghidra_data_type_write",
            "ghidra_batch");
    for (String writeTool : destructiveWrites) {
      Map<String, Object> annotations = annotations(byName.get(writeTool));
      assertEquals(Boolean.FALSE, annotations.get("readOnlyHint"), writeTool);
      assertEquals(Boolean.TRUE, annotations.get("destructiveHint"), writeTool);
    }

    assertFalse(byName.containsKey("ghidra_address_write"));
    assertFalse(byName.containsKey("ghidra_decompilation_write"));
    assertFalse(byName.containsKey("ghidra_reference_write"));
    assertFalse(byName.containsKey("ghidra_batch_write"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void publishesTypedParamsSchemasAndRequiredKeysPerMultiOperationTool() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    Set<String> parameterlessTools = Set.of("ghidra_bridge_write", "ghidra_program_write");

    for (Map<String, Object> tool : registry.listTools()) {
      String name = String.valueOf(tool.get("name"));
      if ("ghidra_help".equals(name)) {
        continue;
      }
      Map<String, Object> inputSchema = (Map<String, Object>) tool.get("inputSchema");
      Map<String, Object> properties = (Map<String, Object>) inputSchema.get("properties");
      Map<String, Object> operationSchema = (Map<String, Object>) properties.get("operation");
      List<String> operations = (List<String>) operationSchema.get("enum");
      Map<String, Object> params = (Map<String, Object>) properties.get("params");
      assertEquals("object", params.get("type"), name);
      Map<String, Object> paramProperties = (Map<String, Object>) params.get("properties");
      assertNotNull(paramProperties, name);
      if (parameterlessTools.contains(name)) {
        assertTrue(paramProperties.isEmpty(), name);
      } else {
        assertFalse(paramProperties.isEmpty(), name);
      }

      String description = String.valueOf(params.get("description"));
      if (operations.size() > 1) {
        assertTrue(description.contains("Required keys by operation:"), name);
        for (String op : operations) {
          assertTrue(description.contains("`" + op + "`"), name + " -> " + op);
        }
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void preservesLegacyDispatchAndEnrichesDomainHelp() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());

    MethodDescriptor legacyPatch = registry.findTool("ghidra_function", "patch");
    MethodDescriptor splitPatch = registry.findTool("ghidra_function_write", "patch");
    assertNotNull(legacyPatch);
    assertEquals("function.patch", legacyPatch.name());
    assertEquals(legacyPatch, splitPatch);

    assertNotNull(registry.findTool("ghidra_function", "get"));
    assertNull(registry.findTool("ghidra_function_write", "get"));
    assertFalse(registry.hasTool("ghidra_address_write"));
    assertFalse(registry.hasTool("ghidra_batch_write"));

    Map<String, Object> functionHelp = registry.help(Map.of("domain", "function"));
    assertEquals("ghidra_function", functionHelp.get("domain"));
    List<Map<String, Object>> operations =
        (List<Map<String, Object>>) functionHelp.get("operations");
    assertEquals(10, operations.size());
    for (Map<String, Object> op : operations) {
      assertNotNull(op.get("name"));
      assertNotNull(op.get("method"));
      assertNotNull(op.get("description"));
      assertTrue(op.get("inputSchema") instanceof Map<?, ?>);
      assertTrue(op.get("outputSchema") instanceof Map<?, ?>);
      assertTrue(op.get("effects") instanceof Map<?, ?>);
    }

    Map<String, Object> writeHelp = registry.help(Map.of("domain", "ghidra_function_write"));
    assertEquals("ghidra_function_write", writeHelp.get("domain"));
    List<Map<String, Object>> writeOperations =
        (List<Map<String, Object>>) writeHelp.get("operations");
    assertEquals(7, writeOperations.size());

    assertThrows(
        IllegalArgumentException.class,
        () -> registry.help(Map.of("domain", "ghidra_function_write", "operation", "get")));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> annotations(Map<String, Object> tool) {
    assertNotNull(tool);
    return (Map<String, Object>) tool.get("annotations");
  }

  private static void assertNoForbiddenSchemaKeys(String toolName, Object value) {
    if (value instanceof Map<?, ?> map) {
      for (String forbidden : FORBIDDEN_SCHEMA_KEYS) {
        assertFalse(map.containsKey(forbidden), toolName + " contains " + forbidden);
      }
      for (Object child : map.values()) {
        assertNoForbiddenSchemaKeys(toolName, child);
      }
    } else if (value instanceof List<?> list) {
      for (Object item : list) {
        assertNoForbiddenSchemaKeys(toolName, item);
      }
    }
  }
}
