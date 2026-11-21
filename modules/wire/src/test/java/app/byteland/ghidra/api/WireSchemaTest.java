package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class WireSchemaTest {
  @Test
  void unknownFieldIncludesSortedAllowedFieldsAndContainerSuggestions() {
    Map<String, Object> internal =
        ApiSchemaCatalog.scanListInput(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    "name", WireSchema.string(),
                    "start", WireSchema.string(),
                    "end", WireSchema.string())));
    StrictObjectCodec codec =
        new StrictObjectCodec(StrictObjectCodec.canonicalSchema(internal), internal);

    ApiException limitError =
        assertThrows(ApiException.class, () -> codec.decode(Map.of("limit", 10), ""));
    assertEquals("unknown_field", limitError.error().code());
    assertEquals("/limit", limitError.error().target());
    assertEquals(
        List.of("filter", "page", "projection", "scan"),
        limitError.error().details().get("allowed_fields"));
    assertEquals("page.limit", limitError.error().details().get("suggested_field"));
    assertTrue(limitError.getMessage().contains("use page.limit"));

    ApiException timeoutError =
        assertThrows(ApiException.class, () -> codec.decode(Map.of("timeout_ms", 500), ""));
    assertEquals("scan.timeout_ms", timeoutError.error().details().get("suggested_field"));
    assertTrue(timeoutError.getMessage().contains("use scan.timeout_ms"));

    ApiException fieldsError =
        assertThrows(ApiException.class, () -> codec.decode(Map.of("fields", List.of("name")), ""));
    assertEquals("projection.fields", fieldsError.error().details().get("suggested_field"));
    assertTrue(fieldsError.getMessage().contains("use projection.fields"));

    ApiException startAtRootError =
        assertThrows(ApiException.class, () -> codec.decode(Map.of("start", "0x1000"), ""));
    assertEquals("scan.range.start", startAtRootError.error().details().get("suggested_field"));
    assertTrue(startAtRootError.getMessage().contains("use scan.range.start"));

    ApiException startInFilterError =
        assertThrows(
            ApiException.class,
            () -> codec.decode(Map.of("filter", Map.of("start", "0x1000")), ""));
    assertEquals("/filter/start", startInFilterError.error().target());
    assertEquals(List.of("name"), startInFilterError.error().details().get("allowed_fields"));
    assertEquals("scan.range.start", startInFilterError.error().details().get("suggested_field"));
  }

  @Test
  void invalidEnumReportsSortedAllowedValuesInDetailsAndMessage() {
    Map<String, Object> schema = WireSchema.stringEnum("repeatable", "eol", "plate");
    ApiException error =
        assertThrows(ApiException.class, () -> WireSchema.validate("bogus", schema, "/type"));
    assertEquals("invalid_enum", error.error().code());
    assertEquals("/type", error.error().target());
    assertEquals(
        List.of("eol", "plate", "repeatable"), error.error().details().get("allowed_values"));
    assertTrue(error.getMessage().contains("[eol, plate, repeatable]"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void oneOfSelectsMatchingKindBranchAndIncludesAllBranchErrors() {
    Map<String, Object> addressBranch =
        WireSchema.object(
            Map.of(
                "kind", WireSchema.stringEnum("address"),
                "address", WireSchema.nonBlankString()),
            "kind",
            "address");
    Map<String, Object> functionBranch =
        WireSchema.object(
            Map.of(
                "kind", WireSchema.stringEnum("function"),
                "entry", WireSchema.nonBlankString()),
            "kind",
            "entry");
    Map<String, Object> rangeBranch =
        WireSchema.object(
            Map.of(
                "kind", WireSchema.stringEnum("range"),
                "start", WireSchema.nonBlankString(),
                "end", WireSchema.nonBlankString()),
            "kind",
            "start");
    Map<String, Object> union = WireSchema.oneOf(addressBranch, functionBranch, rangeBranch);

    ApiException missingEntry =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate(Map.of("kind", "function"), union, "/selector"));
    assertEquals("invalid_union", missingEntry.error().code());
    assertEquals("/selector/entry", missingEntry.error().target());
    assertTrue(missingEntry.getMessage().contains("/selector/entry is required"));
    List<Map<String, Object>> branchErrors =
        (List<Map<String, Object>>) missingEntry.error().details().get("branch_errors");
    assertEquals(3, branchErrors.size());

    ApiException unknownFieldOnKind =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("kind", "function", "entry", "0x1000", "address", "0x1000"),
                    union,
                    "/selector"));
    assertEquals("invalid_union", unknownFieldOnKind.error().code());
    assertEquals("/selector/address", unknownFieldOnKind.error().target());
    assertEquals(
        List.of("entry", "kind"), unknownFieldOnKind.error().details().get("allowed_fields"));
    List<Map<String, Object>> nestedBranchErrors =
        (List<Map<String, Object>>) unknownFieldOnKind.error().details().get("branch_errors");
    assertEquals(3, nestedBranchErrors.size());
  }
}
