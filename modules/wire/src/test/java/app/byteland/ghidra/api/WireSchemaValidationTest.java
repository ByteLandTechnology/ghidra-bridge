package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedClass;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.Test;

class WireSchemaValidationTest {

  @Test
  void validatesOneOfUnionsAndPreservesFirstBranchFailureDiagnostics() {
    Map<String, Object> selectorSchema = ApiSchemaCatalog.flowSelector();

    assertDoesNotThrow(() ->
        WireSchema.validate(
            Map.of("kind", "address", "address", "ram:00100000"), selectorSchema, "/selector"));
    assertDoesNotThrow(() ->
        WireSchema.validate(
            Map.of("kind", "function", "entry", "ram:00100000"), selectorSchema, "/selector"));
    assertDoesNotThrow(() ->
        WireSchema.validate(
            Map.of("kind", "range", "start", "ram:00100000", "end", "ram:00100020"),
            selectorSchema,
            "/selector"));

    // Zero branches match: reports invalid_union with message and target from the first branch.
    ApiException zeroMatch =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate(Map.of("kind", "function"), selectorSchema, "/selector"));
    assertEquals(400, zeroMatch.status());
    assertEquals("invalid_union", zeroMatch.error().code());
    assertEquals("/selector/address is required", zeroMatch.error().message());
    assertEquals("/selector/address", zeroMatch.error().target());

    // Multiple branches match and no branch failed: reports exact-one-schema message.
    Map<String, Object> overlapping =
        WireSchema.oneOf(WireSchema.string(), WireSchema.nonBlankString());
    ApiException multipleWithoutFailure =
        assertThrows(ApiException.class, () -> WireSchema.validate("hello", overlapping, "/value"));
    assertEquals(400, multipleWithoutFailure.status());
    assertEquals("invalid_union", multipleWithoutFailure.error().code());
    assertEquals("/value must match exactly one schema", multipleWithoutFailure.error().message());
    assertEquals("/value", multipleWithoutFailure.error().target());

    // Multiple branches match with a final failed branch: reports that failed branch.
    Map<String, Object> overlappingWithTrailingFailure =
        WireSchema.oneOf(
            WireSchema.string(), WireSchema.nonBlankString(), WireSchema.integer(0, 10));
    ApiException trailingFailure =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate("hello", overlappingWithTrailingFailure, "/value"));
    assertEquals(400, trailingFailure.status());
    assertEquals("invalid_union", trailingFailure.error().code());
    assertEquals("/value must be an integer", trailingFailure.error().message());
    assertEquals("/value", trailingFailure.error().target());

    // Multiple branches match after an earlier branch failed: reports the first failed branch.
    Map<String, Object> overlappingAfterFailure =
        WireSchema.oneOf(
            WireSchema.object(Map.of("id", WireSchema.string()), "id"),
            WireSchema.openObject(),
            WireSchema.any());
    ApiException multipleAfterPriorFailure =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate(Map.of("other", "x"), overlappingAfterFailure, "/payload"));
    assertEquals(400, multipleAfterPriorFailure.status());
    assertEquals("invalid_union", multipleAfterPriorFailure.error().code());
    assertEquals("/payload/id is required", multipleAfterPriorFailure.error().message());
    assertEquals("/payload/id", multipleAfterPriorFailure.error().target());

    // Branch 1 matches, branch 2 fails, branch 3 matches: reports branch 2.
    Map<String, Object> middleFailureWithTwoMatches =
        WireSchema.oneOf(
            WireSchema.openObject(),
            WireSchema.object(Map.of("id", WireSchema.string()), "id"),
            WireSchema.any());
    ApiException middleFailure =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(Map.of("other", "x"), middleFailureWithTwoMatches, "/payload"));
    assertEquals("invalid_union", middleFailure.error().code());
    assertEquals("/payload/id is required", middleFailure.error().message());
    assertEquals("/payload/id", middleFailure.error().target());

    // Empty oneOf reports must match exactly one schema.
    Map<String, Object> emptyUnion = WireSchema.oneOf(List.of());
    ApiException emptyFailure =
        assertThrows(ApiException.class, () -> WireSchema.validate("x", emptyUnion, "/empty"));
    assertEquals("invalid_union", emptyFailure.error().code());
    assertEquals("/empty must match exactly one schema", emptyFailure.error().message());
    assertEquals("/empty", emptyFailure.error().target());
  }

  @Test
  void validatesRecursiveDataTypeReferenceSchemasAndDeepPointers() {
    Map<String, Object> schema =
        WireSchema.withDefinitions(
            WireSchema.object(Map.of("data_type", WireSchema.dataTypeReference()), "data_type"));

    Map<String, Object> validNestedType =
        Map.of(
            "data_type",
            Map.of(
                "kind",
                "pointer",
                "target",
                Map.of(
                    "kind",
                    "array",
                    "count",
                    16,
                    "element",
                    Map.of(
                        "kind",
                        "pointer",
                        "target",
                        Map.of("kind", "named", "name", "uint32_t")))));
    assertDoesNotThrow(() -> WireSchema.validate(validNestedType, schema, "/resource"));

    assertDoesNotThrow(() ->
        WireSchema.validate(
            Map.of("data_type", Map.of("kind", "untyped_pointer")), schema, "/resource"));

    // Invalid leaf in recursive data_type_reference reports invalid_union with first branch
    // failure.
    Map<String, Object> invalidLeaf =
        Map.of(
            "data_type",
            Map.of(
                "kind",
                "pointer",
                "target",
                Map.of(
                    "kind",
                    "array",
                    "count",
                    0,
                    "element",
                    Map.of("kind", "named", "name", "uint32_t"))));
    ApiException ex =
        assertThrows(
            ApiException.class, () -> WireSchema.validate(invalidLeaf, schema, "/resource"));
    assertEquals(400, ex.status());
    assertEquals("invalid_union", ex.error().code());
    assertEquals("/resource/data_type/name is required", ex.error().message());
    assertEquals("/resource/data_type/name", ex.error().target());

    // Direct recursive schema where pointer is the first union branch reports deep leaf pointer.
    Map<String, Object> pointerFirstDef = new LinkedHashMap<>();
    pointerFirstDef.put(ApiVocabulary.TYPE, ApiVocabulary.OBJECT);
    pointerFirstDef.put(ApiVocabulary.ADDITIONAL_PROPERTIES, false);
    pointerFirstDef.put(ApiVocabulary.REQUIRED, List.of("next"));
    pointerFirstDef.put(
        ApiVocabulary.PROPERTIES, Map.of("next", Map.of(ApiVocabulary.REFERENCE, "#/$defs/node")));
    Map<String, Object> leafDef =
        WireSchema.object(Map.of("leaf", WireSchema.nonBlankString()), "leaf");
    Map<String, Object> customRecursive = new LinkedHashMap<>();
    customRecursive.put(ApiVocabulary.REFERENCE, "#/$defs/node");
    customRecursive.put(
        ApiVocabulary.DEFINITIONS, Map.of("node", WireSchema.oneOf(pointerFirstDef, leafDef)));

    Map<String, Object> badDeepChain =
        Map.of("next", Map.of("next", Map.of("next", Map.of("leaf", ""))));
    ApiException deepEx =
        assertThrows(
            ApiException.class, () -> WireSchema.validate(badDeepChain, customRecursive, "/root"));
    assertEquals("invalid_union", deepEx.error().code());
    assertEquals("/root/next/next/next/next is required", deepEx.error().message());
    assertEquals("/root/next/next/next/next", deepEx.error().target());
  }

  @Test
  void escapesPropertyPointersWhileKeepingRawNamesOnMissingAndUnknownFields() {
    Map<String, Object> nestedChild =
        WireSchema.object(Map.of("val~1/leaf", WireSchema.integer(1, 10)), "raw/required~field");
    Map<String, Object> rootSchema =
        WireSchema.object(Map.of("a/b~c", WireSchema.array(nestedChild, 1, 5)), "a/b~c");

    // Known property and array element traversal escapes ~ as ~0 and / as ~1.
    Map<String, Object> invalidValuePayload =
        Map.of("a/b~c", List.of(Map.of("raw/required~field", "unused", "val~1/leaf", 99)));
    // Add raw/required~field to properties for value test:
    Map<String, Object> nestedWithRequiredProp =
        WireSchema.object(
            Map.of(
                "raw/required~field", WireSchema.string(),
                "val~1/leaf", WireSchema.integer(1, 10)),
            "raw/required~field");
    Map<String, Object> schemaForValueCheck =
        WireSchema.object(Map.of("a/b~c", WireSchema.array(nestedWithRequiredProp, 1, 5)), "a/b~c");

    ApiException valueFailure =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate(invalidValuePayload, schemaForValueCheck, "/params"));
    assertEquals("invalid_value", valueFailure.error().code());
    assertEquals("/params/a~1b~0c/0/val~01~1leaf must be in 1..10", valueFailure.error().message());
    assertEquals("/params/a~1b~0c/0/val~01~1leaf", valueFailure.error().target());

    // Absent required field keeps raw field name on leaf and escapes ancestor segments.
    ApiException missingFailure =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("a/b~c", List.of(Map.of())), schemaForValueCheck, "/params"));
    assertEquals("missing_field", missingFailure.error().code());
    assertEquals(
        "/params/a~1b~0c/0/raw/required~field is required", missingFailure.error().message());
    assertEquals("/params/a~1b~0c/0/raw/required~field", missingFailure.error().target());

    // Unknown field keeps raw field name on leaf and escapes ancestor segments.
    ApiException unknownFailure =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of(
                        "a/b~c", List.of(Map.of("raw/required~field", "ok", "extra/raw~key", 1))),
                    schemaForValueCheck,
                    ""));
    assertEquals("unknown_field", unknownFailure.error().code());
    assertEquals("/a~1b~0c/0/extra/raw~key is not allowed", unknownFailure.error().message());
    assertEquals("/a~1b~0c/0/extra/raw~key", unknownFailure.error().target());

    // Verify rootSchema itself also rejects unknown raw/required~field when absent from properties.
    ApiException unconfiguredRequired =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("a/b~c", List.of(Map.of("raw/required~field", "x"))),
                    rootSchema,
                    "/params"));
    assertEquals("unknown_field", unconfiguredRequired.error().code());
  }

  @Test
  void validatesPrimitiveAndContainerEdgeCasesAndCodecTranslation() {
    // Nullable schema accepts null and inner type, rejects wrong type.
    Map<String, Object> nullableString = WireSchema.nullable(WireSchema.nonBlankString());
    assertDoesNotThrow(() -> WireSchema.validate(null, nullableString, "/comment"));
    assertDoesNotThrow(() -> WireSchema.validate("note", nullableString, "/comment"));
    ApiException badNullable =
        assertThrows(ApiException.class, () -> WireSchema.validate("", nullableString, "/comment"));
    assertEquals("invalid_union", badNullable.error().code());
    assertEquals("/comment must not be empty", badNullable.error().message());

    // Integer accepts Byte/Short/Integer/Long and rejects Double.
    Map<String, Object> intSchema = WireSchema.integer(-5, 5);
    assertDoesNotThrow(() -> WireSchema.validate((byte) 1, intSchema, "/n"));
    assertDoesNotThrow(() -> WireSchema.validate((short) -5, intSchema, "/n"));
    assertDoesNotThrow(() -> WireSchema.validate(5L, intSchema, "/n"));
    ApiException floatForInt =
        assertThrows(ApiException.class, () -> WireSchema.validate(1.0, intSchema, "/n"));
    assertEquals("invalid_type", floatForInt.error().code());

    // Number rejects NaN and Infinity.
    Map<String, Object> numSchema = WireSchema.number(0.0, 100.0);
    assertDoesNotThrow(() -> WireSchema.validate(42.5, numSchema, "/progress"));
    ApiException nanFailure =
        assertThrows(
            ApiException.class, () -> WireSchema.validate(Double.NaN, numSchema, "/progress"));
    assertEquals("invalid_value", nanFailure.error().code());
    assertEquals("/progress must be finite", nanFailure.error().message());

    // Object non-text keys and property count bounds.
    Map<Object, Object> nonStringKeyMap = new LinkedHashMap<>();
    nonStringKeyMap.put(123, "bad");
    ApiException invalidField =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate(nonStringKeyMap, WireSchema.openObject(), "/obj"));
    assertEquals("invalid_field", invalidField.error().code());
    assertEquals("/obj field names must be strings", invalidField.error().message());

    Map<String, Object> nonEmpty = ApiSchemaCatalog.nonEmptyObject(Map.of("a", WireSchema.bool()));
    ApiException emptyPatch =
        assertThrows(ApiException.class, () -> WireSchema.validate(Map.of(), nonEmpty, "/patch"));
    assertEquals("invalid_count", emptyPatch.error().code());

    // JsonValueCodec translates output schema failure into 500 invalid_response with exact target.
    JsonValueCodec codec =
        new JsonValueCodec(WireSchema.object(Map.of("ok", WireSchema.bool()), "ok"));
    ApiException invalidResponse =
        assertThrows(ApiException.class, () -> codec.encode(Map.of("ok", "nope")));
    assertEquals(500, invalidResponse.status());
    assertEquals("invalid_response", invalidResponse.error().code());
    assertEquals("/result/ok", invalidResponse.error().target());
  }

  @Test
  void throwsIllegalStateExceptionImmediatelyOnMalformedSchemas() {
    Map<String, Object> unresolvedRef = Map.of(ApiVocabulary.REFERENCE, "#/$defs/does_not_exist");
    assertThrows(
        IllegalStateException.class, () -> WireSchema.validate("x", unresolvedRef, "/target"));

    // Unresolved $ref inside a later oneOf branch still throws IllegalStateException even if an
    // earlier branch matched.
    Map<String, Object> unionWithBadBranch = WireSchema.oneOf(WireSchema.string(), unresolvedRef);
    assertThrows(
        IllegalStateException.class,
        () -> WireSchema.validate("valid", unionWithBadBranch, "/target"));

    Map<String, Object> unsupportedType = Map.of(ApiVocabulary.TYPE, "tuple");
    assertThrows(
        IllegalStateException.class, () -> WireSchema.validate("x", unsupportedType, "/target"));
  }

  @Test
  void validatesBridgeErrorCodePatternAndStatusBounds() {
    BridgeError valid =
        assertDoesNotThrow(
            () -> new BridgeError(400, "invalid_union_2", "bad union", "/x", Map.of()));
    assertEquals("invalid_union_2", valid.code());

    List<String> invalidCodes =
        List.of(
            "",
            "InvalidCode",
            "invalid-code",
            "2invalid",
            "_leading_underscore",
            "trailing_space ",
            "invalid_code\n",
            "invalid.code");
    for (String badCode : invalidCodes) {
      IllegalArgumentException ex =
          assertThrows(
              IllegalArgumentException.class,
              () -> new BridgeError(400, badCode, "message", "/x", Map.of()),
              "Expected code to be rejected: " + badCode);
      assertEquals("bridge error code must be snake_case", ex.getMessage());
    }

    assertThrows(
        IllegalArgumentException.class,
        () -> new BridgeError(400, null, "message", "/x", Map.of()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new BridgeError(200, "invalid_type", "message", "/x", Map.of()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new BridgeError(600, "invalid_type", "message", "/x", Map.of()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new BridgeError(400, "invalid_type", "   ", "/x", Map.of()));
  }

  @Test
  void throwsZeroApiExceptionsOnValidUnionAndDecompilationPayloads() throws Exception {
    ApiCatalog catalog = ApiRegistry.catalog();
    Map<String, Object> functionListSchema =
        catalog.methods().stream()
            .filter(method -> method.name().equals("function.list"))
            .findFirst()
            .orElseThrow()
            .outputSchema();
    Map<String, Object> decompilationSchema =
        catalog.methods().stream()
            .filter(method -> method.name().equals("decompilation.get"))
            .findFirst()
            .orElseThrow()
            .outputSchema();

    Map<String, Object> functionItem = new LinkedHashMap<>();
    functionItem.put("entry", "ram:00100000");
    functionItem.put("name", "main");
    functionItem.put(
        "return_type", Map.of("kind", "pointer", "target", Map.of("kind", "untyped_pointer")));
    functionItem.put("return_storage", Map.of("kind", "register", "register", "RAX"));
    functionItem.put(
        "parameters",
        List.of(
            Map.of(
                "ordinal",
                0,
                "name",
                "argc",
                "data_type",
                Map.of("kind", "named", "name", "int"),
                "storage",
                Map.of("kind", "register", "register", "EDI")),
            Map.of(
                "ordinal",
                1,
                "name",
                "argv",
                "data_type",
                Map.of(
                    "kind",
                    "pointer",
                    "target",
                    Map.of("kind", "pointer", "target", Map.of("kind", "named", "name", "char"))),
                "storage",
                Map.of("kind", "serialization", "serialization", "Stack[-0x10]:8"))));
    Map<String, Object> functionListPayload = Map.of("items", List.of(functionItem));

    Map<String, Object> decompilationPayload =
        Map.of(
            "entry",
            "ram:00100000",
            "name",
            "main",
            "c",
            "int main(void) { return 0; }",
            "tokens",
            List.of(Map.of("kind", "keyword", "text", "return", "address", "ram:00100004")),
            "lines",
            List.of(
                Map.of(
                    "number",
                    0,
                    "indent",
                    1,
                    "tokens",
                    List.of(
                        Map.of(
                            "kind",
                            "keyword",
                            "text",
                            "return",
                            "start",
                            2,
                            "end",
                            8,
                            "location_address",
                            "ram:00100004",
                            "code_unit_address",
                            "ram:00100004")))));

    Path recordingPath = Files.createTempFile("wire-schema-test-", ".jfr");
    try {
      try (Recording recording = new Recording()) {
        recording.enable("jdk.JavaExceptionThrow").withoutThreshold();
        recording.start();
        for (int i = 0; i < 50; i++) {
          WireSchema.validate(functionListPayload, functionListSchema, "/result");
          WireSchema.validate(decompilationPayload, decompilationSchema, "/result");
        }
        recording.stop();
        recording.dump(recordingPath);
      }
      long apiExceptionCount = 0;
      try (RecordingFile file = new RecordingFile(recordingPath)) {
        while (file.hasMoreEvents()) {
          RecordedEvent event = file.readEvent();
          if ("jdk.JavaExceptionThrow".equals(event.getEventType().getName())) {
            RecordedClass thrownClass = event.getValue("thrownClass");
            if (thrownClass != null && ApiException.class.getName().equals(thrownClass.getName())) {
              apiExceptionCount++;
            }
          }
        }
      }
      assertEquals(0L, apiExceptionCount);
    } finally {
      Files.deleteIfExists(recordingPath);
    }
  }

  @Test
  void validatesNullTargetsAndEmptyRootsWithExactDiagnostics() {
    Map<String, Object> itemSchema =
        WireSchema.object(
            Map.of(
                "a/b", WireSchema.nonBlankString(),
                "count", WireSchema.integer(1, 5),
                "ratio", WireSchema.number(0.0, 1.0)),
            "a/b");
    Map<String, Object> rootSchema =
        WireSchema.object(Map.of("items", WireSchema.array(itemSchema, 1, 2)), "items");

    Map<String, Object> validPayload =
        Map.of("items", List.of(Map.of("a/b", "ok", "count", 3, "ratio", 0.5)));
    assertDoesNotThrow(() -> WireSchema.validate(validPayload, rootSchema, null));
    assertDoesNotThrow(() -> WireSchema.validate(validPayload, rootSchema, ""));

    // Null target root preserves null target at root and prefixes child pointers with "null/".
    ApiException nullRootType =
        assertThrows(ApiException.class, () -> WireSchema.validate(123, WireSchema.string(), null));
    assertEquals("invalid_type", nullRootType.error().code());
    assertEquals("null must be a string", nullRootType.error().message());
    assertEquals(null, nullRootType.error().target());
    assertEquals(false, nullRootType.error().toMap().containsKey("target"));

    ApiException nullRootRange =
        assertThrows(
            ApiException.class, () -> WireSchema.validate(9.5, WireSchema.number(0.0, 1.0), null));
    assertEquals("invalid_value", nullRootRange.error().code());
    assertEquals("null must be in 0.0..1.0", nullRootRange.error().message());
    assertEquals(null, nullRootRange.error().target());

    ApiException nullMissingField =
        assertThrows(ApiException.class, () -> WireSchema.validate(Map.of(), rootSchema, null));
    assertEquals("missing_field", nullMissingField.error().code());
    assertEquals("null/items is required", nullMissingField.error().message());
    assertEquals("null/items", nullMissingField.error().target());

    ApiException nullUnknownField =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("items", List.of(Map.of("a/b", "ok")), "extra", 1), rootSchema, null));
    assertEquals("unknown_field", nullUnknownField.error().code());
    assertEquals("null/extra is not allowed", nullUnknownField.error().message());
    assertEquals("null/extra", nullUnknownField.error().target());

    ApiException nullNestedRange =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("items", List.of(Map.of("a/b", "ok", "count", 9))), rootSchema, null));
    assertEquals("invalid_value", nullNestedRange.error().code());
    assertEquals("null/items/0/count must be in 1..5", nullNestedRange.error().message());
    assertEquals("null/items/0/count", nullNestedRange.error().target());

    Map<String, Object> overlapping =
        WireSchema.oneOf(WireSchema.string(), WireSchema.nonBlankString());
    ApiException nullUnionOverlap =
        assertThrows(ApiException.class, () -> WireSchema.validate("ok", overlapping, null));
    assertEquals("invalid_union", nullUnionOverlap.error().code());
    assertEquals("null must match exactly one schema", nullUnionOverlap.error().message());
    assertEquals(null, nullUnionOverlap.error().target());

    // Empty root keeps empty target at root and formats child pointers from "/".
    ApiException emptyRootType =
        assertThrows(ApiException.class, () -> WireSchema.validate("bad", rootSchema, ""));
    assertEquals("invalid_type", emptyRootType.error().code());
    assertEquals(" must be an object", emptyRootType.error().message());
    assertEquals("", emptyRootType.error().target());

    ApiException emptyRootEnum =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate("z", WireSchema.stringEnum("a", "b"), ""));
    assertEquals("invalid_enum", emptyRootEnum.error().code());
    assertEquals(" has an unsupported value", emptyRootEnum.error().message());
    assertEquals("", emptyRootEnum.error().target());

    ApiException emptyArrayCount =
        assertThrows(
            ApiException.class,
            () -> WireSchema.validate(Map.of("items", List.of()), rootSchema, ""));
    assertEquals("invalid_count", emptyArrayCount.error().code());
    assertEquals("/items must contain 1..2 items", emptyArrayCount.error().message());
    assertEquals("/items", emptyArrayCount.error().target());

    ApiException emptyMissingField =
        assertThrows(ApiException.class, () -> WireSchema.validate(Map.of(), rootSchema, ""));
    assertEquals("missing_field", emptyMissingField.error().code());
    assertEquals("/items is required", emptyMissingField.error().message());
    assertEquals("/items", emptyMissingField.error().target());

    ApiException emptyNestedLeaf =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("items", List.of(Map.of("a/b", ""), Map.of("a/b", "ok"))),
                    rootSchema,
                    ""));
    assertEquals("invalid_value", emptyNestedLeaf.error().code());
    assertEquals("/items/0/a~1b must not be empty", emptyNestedLeaf.error().message());
    assertEquals("/items/0/a~1b", emptyNestedLeaf.error().target());

    ApiException emptyNumberRange =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("items", List.of(Map.of("a/b", "ok", "ratio", 2.5))), rootSchema, ""));
    assertEquals("invalid_value", emptyNumberRange.error().code());
    assertEquals("/items/0/ratio must be in 0.0..1.0", emptyNumberRange.error().message());
    assertEquals("/items/0/ratio", emptyNumberRange.error().target());

    ApiException emptyUnionOverlap =
        assertThrows(ApiException.class, () -> WireSchema.validate("ok", overlapping, ""));
    assertEquals("invalid_union", emptyUnionOverlap.error().code());
    assertEquals(" must match exactly one schema", emptyUnionOverlap.error().message());
    assertEquals("", emptyUnionOverlap.error().target());
  }

  @Test
  void validatesNestedOneOfUnionsAndMalformedInnerBranches() {
    Map<String, Object> registerStorage =
        WireSchema.object(
            Map.of("kind", WireSchema.stringEnum("register"), "name", WireSchema.nonBlankString()),
            "kind",
            "name");
    Map<String, Object> stackStorage =
        WireSchema.object(
            Map.of(
                "kind", WireSchema.stringEnum("stack"), "offset", WireSchema.integer(-4096, 4096)),
            "kind",
            "offset");
    Map<String, Object> concreteStorage = WireSchema.oneOf(registerStorage, stackStorage);
    Map<String, Object> autoStorage =
        WireSchema.object(Map.of("kind", WireSchema.stringEnum("auto")), "kind");
    Map<String, Object> nestedUnion =
        WireSchema.oneOf(
            concreteStorage, autoStorage, Map.of(ApiVocabulary.TYPE, ApiVocabulary.NULL));

    assertDoesNotThrow(() ->
        WireSchema.validate(Map.of("kind", "register", "name", "RAX"), nestedUnion, "/storage"));
    assertDoesNotThrow(
        () -> WireSchema.validate(Map.of("kind", "stack", "offset", -16), nestedUnion, "/storage"));
    assertDoesNotThrow(() -> WireSchema.validate(Map.of("kind", "auto"), nestedUnion, "/storage"));
    assertDoesNotThrow(() -> WireSchema.validate(null, nestedUnion, "/storage"));

    // Zero matches across nested oneOf preserves the first inner branch diagnostic.
    ApiException zeroMatch =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("kind", "stack", "offset", 99999), nestedUnion, "/storage"));
    assertEquals("invalid_union", zeroMatch.error().code());
    assertEquals("/storage/name is required", zeroMatch.error().message());
    assertEquals("/storage/name", zeroMatch.error().target());

    // Inner oneOf matches and outer second branch also matches without any outer failure.
    Map<String, Object> outerDoubleMatch =
        WireSchema.oneOf(concreteStorage, WireSchema.openObject());
    ApiException doubleMatch =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("kind", "stack", "offset", -8), outerDoubleMatch, "/storage"));
    assertEquals("invalid_union", doubleMatch.error().code());
    assertEquals("/storage must match exactly one schema", doubleMatch.error().message());
    assertEquals("/storage", doubleMatch.error().target());

    // Failed inner oneOf before two outer branches match reports first inner failure.
    Map<String, Object> failedInnerThenTwoMatches =
        WireSchema.oneOf(concreteStorage, WireSchema.openObject(), WireSchema.any());
    ApiException failedInner =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(Map.of("kind", "auto"), failedInnerThenTwoMatches, "/storage"));
    assertEquals("invalid_union", failedInner.error().code());
    assertEquals("/storage/name is required", failedInner.error().message());
    assertEquals("/storage/name", failedInner.error().target());

    // Malformed inner branch inside a later nested oneOf throws IllegalStateException immediately.
    Map<String, Object> badInner =
        WireSchema.oneOf(
            WireSchema.integer(0, 10), Map.of(ApiVocabulary.REFERENCE, "#/$defs/missing_inner"));
    Map<String, Object> validFirstWithMalformedNested =
        WireSchema.oneOf(WireSchema.string(), badInner);
    assertThrows(
        IllegalStateException.class,
        () -> WireSchema.validate("valid", validFirstWithMalformedNested, "/value"));
  }
}
