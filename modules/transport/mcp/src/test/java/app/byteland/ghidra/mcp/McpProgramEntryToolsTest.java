package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiRegistry;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpProgramEntryToolsTest {
  @Test
  @SuppressWarnings("unchecked")
  void helpListsImportExportAndEntryPointOperationsUnderProgramWithReadOnlyTrue() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());

    Map<String, Object> domainHelp = registry.help(Map.of("domain", "ghidra_program"));
    List<Map<String, Object>> operations =
        (List<Map<String, Object>>) domainHelp.get("operations");
    List<String> operationNames =
        operations.stream().map(entry -> String.valueOf(entry.get("name"))).toList();
    assertTrue(operationNames.contains("import.list"));
    assertTrue(operationNames.contains("export.list"));
    assertTrue(operationNames.contains("entry_point.list"));

    for (String operation : List.of("import.list", "export.list", "entry_point.list")) {
      assertNotNull(registry.findTool("ghidra_program", operation));
      Map<String, Object> detail =
          registry.help(Map.of("domain", "ghidra_program", "operation", operation));
      assertEquals("ghidra_program", detail.get("domain"));
      assertEquals(operation, detail.get("operation"));
      assertEquals(operation, detail.get("method"));
      Map<?, ?> effects = (Map<?, ?>) detail.get("effects");
      assertEquals(Boolean.TRUE, effects.get("read_only"));
      assertEquals(Boolean.FALSE, effects.get("mutates_program"));
      assertEquals(Boolean.FALSE, effects.get("requires_transaction"));
    }
  }
}
