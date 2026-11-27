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
            "kind", "variable", "text", "iVar1", "start", 2, "end", 7,
            "location_address", "ram:1008", "code_unit_address", "ram:1008",
            "symbol", Map.of(
                "id", "local:1:HASH:5ff83d9281:4",
                "name", "iVar1",
                "address", "ram:1000",
                "type", "Local Var"))));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(line), ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(Map.of(
            "name", "iVar1",
            "data_type", Map.of("kind", "named", "name", "/int"),
            "storage", Map.of("kind", "serialization", "serialization", "HASH:5ff83d9281:4"))),
        ApiSchemaCatalog.outputFieldSchema("local_variables"), "/local_variables"));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(Map.of("address", "ram:1008", "type", "repeatable", "text", "note")),
        ApiSchemaCatalog.outputFieldSchema("comments"), "/comments"));
    assertDoesNotThrow(() -> WireSchema.validate(
        true, ApiSchemaCatalog.outputFieldSchema("comments_complete"), "/comments_complete"));
    assertThrows(ApiException.class, () -> WireSchema.validate(
        List.of(Map.of("number", 0, "indent", 0, "tokens", List.of(Map.of("text", "bad")))),
        ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
  }
}
