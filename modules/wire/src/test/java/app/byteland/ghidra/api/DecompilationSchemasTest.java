package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DecompilationSchemasTest {
  @Test
  void acceptsNativeLayoutAndCommentResults() {
    Map<String, Object> line = Map.of(
        "number", 0, "indent", 2, "tokens", List.of(Map.of(
            "kind", "keyword", "text", "return", "start", 2, "end", 8,
            "location_address", "ram:1008", "code_unit_address", "ram:1008")));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(line), ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(Map.of("address", "ram:1008", "type", "repeatable", "text", "note")),
        ApiSchemaCatalog.outputFieldSchema("comments"), "/comments"));
    assertDoesNotThrow(() -> WireSchema.validate(
        true, ApiSchemaCatalog.outputFieldSchema("comments_complete"), "/comments_complete"));
    assertThrows(ApiException.class, () -> WireSchema.validate(
        List.of(Map.of("number", 0, "indent", 0, "tokens", List.of(Map.of("text", "bad")))),
        ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
  }

  @Test
  void acceptsHighSymbolMetadataOnVariableAndParameterTokens() {
    Map<String, Object> parameterToken = Map.of(
        "kind", "parameter",
        "text", "param_1",
        "start", 12,
        "end", 19,
        "location_address", "ram:00101000",
        "code_unit_address", "ram:00101000",
        "symbol", Map.of(
            "id", "4611686018427387905",
            "name", "param_1",
            "address", "ram:00101000",
            "namespace", "compute_temp",
            "type", "Parameter",
            "source_type", "DEFAULT",
            "primary", false));
    Map<String, Object> variableToken = Map.of(
        "kind", "variable",
        "text", "uVar1",
        "start", 2,
        "end", 7,
        "location_address", "ram:00101008",
        "code_unit_address", "ram:00101008",
        "symbol", Map.of(
            "id", "4611686018427387906",
            "name", "uVar1",
            "address", "ram:00101008",
            "namespace", "compute_temp",
            "type", "Local Var",
            "source_type", "DEFAULT",
            "primary", false));
    List<Map<String, Object>> lines = List.of(
        Map.of("number", 0, "indent", 0, "tokens", List.of(parameterToken)),
        Map.of("number", 1, "indent", 2, "tokens", List.of(variableToken)));
    assertDoesNotThrow(() -> WireSchema.validate(
        lines, ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
    assertThrows(ApiException.class, () -> WireSchema.validate(
        List.of(Map.of("number", 0, "indent", 2, "tokens", List.of(Map.of(
            "kind", "variable",
            "text", "uVar1",
            "start", 2,
            "end", 7,
            "symbol", Map.of("name", "uVar1"))))),
        ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
  }
}
