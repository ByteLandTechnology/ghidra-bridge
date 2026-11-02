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
}
