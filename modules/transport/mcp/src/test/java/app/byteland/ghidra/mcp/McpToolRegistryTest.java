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
  void helpExposesParseCAndCPrototypeSchemas() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    assertEquals(15, registry.listTools().size());

    Map<String, Object> dataTypeOps = registry.help(Map.of("domain", "data_type"));
    List<?> operations = (List<?>) dataTypeOps.get("operations");
    assertTrue(operations.contains("parse_c"));

    Map<String, Object> parseCSchema =
        registry.help(Map.of("domain", "data_type", "operation", "parse_c"));
    assertEquals("data_type.parse_c", parseCSchema.get("method"));
    Map<?, ?> parseCInput = (Map<?, ?>) parseCSchema.get("inputSchema");
    Map<?, ?> parseCProps = (Map<?, ?>) parseCInput.get("properties");
    assertTrue(parseCProps.containsKey("declarations"));
    assertTrue(parseCProps.containsKey("category_path"));
    assertTrue(parseCProps.containsKey("conflict_mode"));

    Map<String, Object> functionPatchSchema =
        registry.help(Map.of("domain", "function", "operation", "patch"));
    assertEquals("function.patch", functionPatchSchema.get("method"));
    Map<?, ?> fnInput = (Map<?, ?>) functionPatchSchema.get("inputSchema");
    Map<?, ?> fnProps = (Map<?, ?>) fnInput.get("properties");
    Map<?, ?> patchObj = (Map<?, ?>) fnProps.get("patch");
    Map<?, ?> patchProps = (Map<?, ?>) patchObj.get("properties");
    assertTrue(patchProps.containsKey("signature"));

    Map<?, ?> defs = (Map<?, ?>) fnInput.get("$defs");
    assertNotNull(defs);
    Map<?, ?> dataTypeRef = (Map<?, ?>) defs.get("data_type_reference");
    List<?> oneOf = (List<?>) dataTypeRef.get("oneOf");
    assertEquals(5, oneOf.size());
  }
}
