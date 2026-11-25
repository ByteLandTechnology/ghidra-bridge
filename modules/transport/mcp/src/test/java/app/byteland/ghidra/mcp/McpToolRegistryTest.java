package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiRegistry;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class McpToolRegistryTest {

  private static final List<String> EXPECTED_TOOL_NAMES =
      List.of(
          "ghidra_help",
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
          "ghidra_data_type",
          "ghidra_batch");

  @Test
  @SuppressWarnings("unchecked")
  void aggregatesDomainAnnotationsAndPreservesFifteenToolSurface() throws Exception {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    List<Map<String, Object>> tools = registry.listTools();
    assertEquals(15, tools.size());
    assertEquals(
        EXPECTED_TOOL_NAMES, tools.stream().map(tool -> (String) tool.get("name")).toList());

    Map<String, Map<String, Object>> byName = new LinkedHashMap<>();
    for (Map<String, Object> tool : tools) {
      byName.put((String) tool.get("name"), tool);
    }

    for (String readOnlyTool :
        List.of("ghidra_help", "ghidra_address", "ghidra_decompilation", "ghidra_reference")) {
      assertEquals(
          annotations(true, false, true),
          byName.get(readOnlyTool).get("annotations"),
          readOnlyTool);
    }

    assertEquals(annotations(false, false, true), byName.get("ghidra_program").get("annotations"));
    assertEquals(
        annotations(false, false, false), byName.get("ghidra_analysis").get("annotations"));

    Set<String> idempotentDomainTools =
        tools.stream()
            .skip(1)
            .filter(
                tool ->
                    Boolean.TRUE.equals(
                        ((Map<String, Object>) tool.get("annotations")).get("idempotentHint")))
            .map(tool -> (String) tool.get("name"))
            .collect(Collectors.toSet());
    assertEquals(
        Set.of(
            "ghidra_bridge",
            "ghidra_program",
            "ghidra_address",
            "ghidra_memory",
            "ghidra_listing",
            "ghidra_decompilation",
            "ghidra_symbol",
            "ghidra_reference"),
        idempotentDomainTools);

    for (String destructiveIdempotent :
        List.of("ghidra_bridge", "ghidra_memory", "ghidra_listing", "ghidra_symbol")) {
      assertEquals(
          annotations(false, true, true),
          byName.get(destructiveIdempotent).get("annotations"),
          destructiveIdempotent);
    }

    for (String destructiveNonIdempotent :
        List.of(
            "ghidra_global_variable",
            "ghidra_function",
            "ghidra_comment",
            "ghidra_data_type",
            "ghidra_batch")) {
      assertEquals(
          annotations(false, true, false),
          byName.get(destructiveNonIdempotent).get("annotations"),
          destructiveNonIdempotent);
    }

    Path checkedInContract = Path.of("..", "..", "..", "docs", "mcp-tools.json").normalize();
    if (Files.isRegularFile(checkedInContract)) {
      Map<String, Object> contract =
          JsonUtil.parseObject(Files.readString(checkedInContract, StandardCharsets.UTF_8));
      List<Map<String, Object>> contractTools = (List<Map<String, Object>>) contract.get("tools");
      assertEquals(15, contractTools.size());
      for (Map<String, Object> contractTool : contractTools) {
        String name = (String) contractTool.get("name");
        assertEquals(
            byName.get(name).get("annotations"), contractTool.get("annotations"), name);
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void exposesBatchQueryInGhidraBatchAndReportsReadOnlyEffectsInHelp() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());

    Map<String, Object> batchDomainHelp = registry.help(Map.of("domain", "ghidra_batch"));
    assertEquals("ghidra_batch", batchDomainHelp.get("domain"));
    assertEquals(List.of("execute", "query"), batchDomainHelp.get("operations"));

    Map<String, Object> queryHelp =
        registry.help(Map.of("domain", "ghidra_batch", "operation", "query"));
    assertEquals("ghidra_batch", queryHelp.get("domain"));
    assertEquals("query", queryHelp.get("operation"));
    assertEquals("batch.query", queryHelp.get("method"));
    Map<String, Object> queryEffects = (Map<String, Object>) queryHelp.get("effects");
    assertTrue((Boolean) queryEffects.get("read_only"));
    assertFalse((Boolean) queryEffects.get("destructive"));
    assertTrue((Boolean) queryEffects.get("idempotent"));
    assertTrue((Boolean) queryEffects.get("allowed_during_analysis"));
    assertFalse((Boolean) queryEffects.get("mutates_program"));
    assertFalse((Boolean) queryEffects.get("requires_transaction"));

    Map<String, Object> executeHelp =
        registry.help(Map.of("domain", "ghidra_batch", "operation", "execute"));
    Map<String, Object> executeEffects = (Map<String, Object>) executeHelp.get("effects");
    assertFalse((Boolean) executeEffects.get("read_only"));
    assertTrue((Boolean) executeEffects.get("destructive"));
  }

  private static Map<String, Object> annotations(
      boolean readOnlyHint, boolean destructiveHint, boolean idempotentHint) {
    return Map.of(
        "readOnlyHint", readOnlyHint,
        "destructiveHint", destructiveHint,
        "idempotentHint", idempotentHint,
        "openWorldHint", false);
  }
}
