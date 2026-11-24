package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ProjectionWireTest {

  record GuardedChild(String safe, String forbidden) {
    @Override
    public String forbidden() {
      throw new AssertionError("unprojected nested component must not be accessed");
    }
  }

  record GuardedResource(
      String id, String selected, String unrequested, GuardedChild nested, List<GuardedChild> list) {
    @Override
    public String unrequested() {
      throw new AssertionError("unprojected root component must not be accessed");
    }
  }

  @Test
  void validatesProjectionFieldsInSinglePassAndPreserves400Errors() throws Exception {
    AtomicInteger listReads = new AtomicInteger();
    AtomicReference<Set<String>> capturedFields = new AtomicReference<>();
    List<String> rawList = List.of("body.start", "name");
    List<String> countingList =
        new AbstractList<>() {
          @Override
          public String get(int index) {
            listReads.incrementAndGet();
            return rawList.get(index);
          }

          @Override
          public int size() {
            return rawList.size();
          }
        };

    Map<String, Object> outputSchema =
        ApiSchemaCatalog.resourceSchema(
            ApiSchemaCatalog.functionFields(), List.of(ApiVocabulary.ENTRY));
    ApiMethod<Object, Object> method =
        new ApiMethod<>(
            "function.get",
            "Test projected method.",
            ApiMethod.MethodEffects.readOnlyMethod(),
            new JsonValueCodec(WireSchema.openObject()),
            new JsonValueCodec(outputSchema),
            ApiSchemaCatalog.functionFields(),
            List.of(ApiVocabulary.ENTRY),
            (ApiMethod.ProjectedHandler<Object, Object>)
                (request, projectedFields) -> {
                  capturedFields.set(projectedFields);
                  return Map.of(
                      "entry", "0x00101000",
                      "body", Map.of("start", "0x00101000"),
                      "name", "main");
                });

    Object encoded = method.invokeDecoded(Map.of("fields", countingList));
    assertEquals(rawList.size(), listReads.get(), "projection.fields must be read in one pass");
    assertEquals(List.of("entry", "body.start", "name"), List.copyOf(capturedFields.get()));
    assertEquals(
        Map.of("entry", "0x00101000", "body", Map.of("start", "0x00101000"), "name", "main"),
        encoded);

    ApiException nonArray =
        assertThrows(ApiException.class, () -> method.invokeDecoded(Map.of("fields", "name")));
    assertEquals(400, nonArray.status());
    assertEquals("invalid_fields", nonArray.error().code());
    assertEquals("/projection/fields", nonArray.error().target());

    for (String badPath : List.of("", "  ", "body.*", "parameters.0", "body.", ".start")) {
      ApiException invalid =
          assertThrows(
              ApiException.class, () -> method.invokeDecoded(Map.of("fields", List.of(badPath))));
      assertEquals(400, invalid.status());
      assertEquals("invalid_fields", invalid.error().code());
      assertEquals("/projection/fields/0", invalid.error().target());
    }

    ApiException duplicate =
        assertThrows(
            ApiException.class,
            () -> method.invokeDecoded(Map.of("fields", List.of("name", "name"))));
    assertEquals(400, duplicate.status());
    assertEquals("duplicate_field", duplicate.error().code());
    assertEquals("/projection/fields/1", duplicate.error().target());

    ApiException duplicateIdentity =
        assertThrows(
            ApiException.class,
            () -> method.invokeDecoded(Map.of("fields", List.of("entry", "entry"))));
    assertEquals(400, duplicateIdentity.status());
    assertEquals("duplicate_field", duplicateIdentity.error().code());
    assertEquals("/projection/fields/1", duplicateIdentity.error().target());

    ApiException unknown =
        assertThrows(
            ApiException.class,
            () -> method.invokeDecoded(Map.of("fields", List.of("not_a_field"))));
    assertEquals(400, unknown.status());
    assertEquals("unknown_field", unknown.error().code());
    assertEquals("/projection/fields/0", unknown.error().target());
  }

  @Test
  void wireValuesSkipsUnrequestedRecordComponentAccessorsAndProjectsDotPaths() {
    GuardedResource resource =
        new GuardedResource(
            "42",
            "kept",
            "boom",
            new GuardedChild("nested-ok", "boom"),
            List.of(new GuardedChild("item-ok", "boom")));

    Set<String> selected =
        new LinkedHashSet<>(List.of("id", "selected", "nested.safe", "list.safe"));
    Map<String, Object> normalized = WireValues.resource(resource, selected);
    assertEquals(
        Map.of(
            "id", "42",
            "selected", "kept",
            "nested", Map.of("safe", "nested-ok"),
            "list", List.of(Map.of("safe", "item-ok"))),
        normalized);

    Map<String, Object> allowedOnly =
        WireValues.resourceAllowed(resource, new LinkedHashSet<>(List.of("selected", "id")));
    assertEquals(
        List.of("id", "selected"),
        List.copyOf(allowedOnly.keySet()),
        "resourceAllowed must preserve RecordComponent declaration order");
    assertEquals(Map.of("id", "42", "selected", "kept"), allowedOnly);

    GuardedResource listSafeResource =
        new GuardedResource("42", "kept", "boom", null, List.of());
    Map<String, Object> allowedWithDotRoot =
        WireValues.resourceAllowed(
            listSafeResource, new LinkedHashSet<>(List.of("list.safe", "selected", "id")));
    assertEquals(
        List.of("id", "selected", "list"),
        List.copyOf(allowedWithDotRoot.keySet()),
        "resourceAllowed with dot-path knownFields must preserve RecordComponent declaration order");
    Map<String, Object> unprojectedList =
        WireValues.list(
            new Page<>(List.of(listSafeResource), 1, 10, null, null),
            null,
            new LinkedHashSet<>(List.of("list.safe", "selected", "id")));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> normalizedItems =
        (List<Map<String, Object>>) unprojectedList.get("items");
    assertEquals(
        List.of("id", "selected", "list"),
        List.copyOf(normalizedItems.getFirst().keySet()),
        "unprojected list must preserve RecordComponent declaration order");
  }

  @Test
  void projectedSchemaValidationAcceptsPartialNestedObjectsAndRejectsInvalidValues() {
    Map<String, Object> functionSchema =
        ApiSchemaCatalog.resourceSchema(
            ApiSchemaCatalog.functionFields(), List.of(ApiVocabulary.ENTRY));
    JsonValueCodec codec = new JsonValueCodec(functionSchema);

    Map<String, Object> partialBody =
        Map.of("entry", "0x00101000", "body", Map.of("start", "0x00101000"));
    assertEquals(
        partialBody, codec.encode(partialBody, new LinkedHashSet<>(List.of("entry", "body.start"))));

    Map<String, Object> partialParamsAndLocals =
        Map.of(
            "entry",
            "0x00101000",
            "parameters",
            List.of(Map.of("name", "argc")),
            "local_variables",
            List.of(Map.of("storage", Map.of("kind", "register", "register", "RAX"))));
    assertEquals(
        partialParamsAndLocals,
        codec.encode(
            partialParamsAndLocals,
            new LinkedHashSet<>(
                List.of("entry", "parameters.name", "local_variables.storage"))));

    // Unprojected extra property in a projected response is rejected.
    ApiException unexpectedField =
        assertThrows(
            ApiException.class,
            () ->
                codec.encode(
                    Map.of("entry", "0x00101000", "name", "main"),
                    new LinkedHashSet<>(List.of("entry"))));
    assertEquals("invalid_response", unexpectedField.error().code());
    assertEquals("unknown_field", ((ApiException) unexpectedField.getCause()).error().code());

    // Wrong value type on a projected nested property is still rejected.
    ApiException wrongNestedType =
        assertThrows(
            ApiException.class,
            () ->
                codec.encode(
                    Map.of("entry", "0x00101000", "body", Map.of("start", 123)),
                    new LinkedHashSet<>(List.of("entry", "body.start"))));
    assertEquals("invalid_response", wrongNestedType.error().code());
    assertEquals("invalid_type", ((ApiException) wrongNestedType.getCause()).error().code());

    // Absent projected required child property inside present parent object is rejected.
    ApiException missingProjectedSubfield =
        assertThrows(
            ApiException.class,
            () ->
                codec.encode(
                    Map.of("entry", "0x00101000", "body", Map.of()),
                    new LinkedHashSet<>(List.of("entry", "body.start"))));
    assertEquals("invalid_response", missingProjectedSubfield.error().code());
    assertEquals(
        "missing_field", ((ApiException) missingProjectedSubfield.getCause()).error().code());

    // Scalar union branch is rejected when only a nested subfield is projected.
    Map<String, Object> dataTypeSchema =
        ApiSchemaCatalog.resourceSchema(ApiSchemaCatalog.dataTypeFields(), List.of("path"));
    ApiException scalarUnionForSubfield =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validateProjected(
                    Map.of("path", "/Callback", "signature", "int Callback(void)"),
                    dataTypeSchema,
                    "/result",
                    new LinkedHashSet<>(List.of("path", "signature.return_type"))));
    assertEquals("invalid_union", scalarUnionForSubfield.error().code());
    assertEquals("/result/signature", scalarUnionForSubfield.error().target());

    // Open and untyped schemas enforce projected child keys and reject scalars on subfield paths.
    Map<String, Object> openSchema =
        WireSchema.object(
            Map.of("id", WireSchema.string(), "meta", WireSchema.any(), "bag", WireSchema.openObject()),
            "id");
    WireSchema.validateProjected(
        Map.of("id", "1", "meta", Map.of("tag", "v1"), "bag", Map.of("nested", 7)),
        openSchema,
        "/result",
        new LinkedHashSet<>(List.of("id", "meta.tag", "bag.nested")));
    ApiException unprojectedOpenChild =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validateProjected(
                    Map.of("id", "1", "bag", Map.of("nested", 7, "extra", 8)),
                    openSchema,
                    "/result",
                    new LinkedHashSet<>(List.of("id", "bag.nested"))));
    assertEquals("unknown_field", unprojectedOpenChild.error().code());
    assertEquals("/result/bag/extra", unprojectedOpenChild.error().target());
    ApiException scalarOnAnySubfield =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validateProjected(
                    Map.of("id", "1", "meta", "raw-string"),
                    openSchema,
                    "/result",
                    new LinkedHashSet<>(List.of("id", "meta.tag"))));
    assertEquals("invalid_type", scalarOnAnySubfield.error().code());
    assertEquals("/result/meta", scalarOnAnySubfield.error().target());

    // Resource schema with an items property alongside resource fields is not treated as a list envelope.
    Map<String, Object> resourceWithItems =
        WireSchema.object(
            Map.of(
                "id", WireSchema.string(),
                "items", WireSchema.array(WireSchema.string(), 0, 10)),
            "id",
            "items");
    WireSchema.validateProjected(
        Map.of("id", "bundle-1"),
        resourceWithItems,
        "/result",
        new LinkedHashSet<>(List.of("id")));
  }

  @Test
  @SuppressWarnings("unchecked")
  void allTwentyEightProjectionEnabledMethodsPreserveParityIdentityCursorsScanAndDotPaths()
      throws Exception {
    ApiRegistry registry = buildTestRegistry();
    List<ApiMethod<Map<String, Object>, Object>> projectedMethods =
        registry.methods().stream().filter(m -> !m.fields().isEmpty() && isReadOnly(m)).toList();
    assertEquals(28, projectedMethods.size(), "expected all 28 projection-enabled read/list methods");

    Map<String, Map<String, Object>> baseParams = sampleRequests();
    assertEquals(28, baseParams.size());

    for (ApiMethod<Map<String, Object>, Object> method : projectedMethods) {
      Map<String, Object> unprojectedParams = baseParams.get(method.name());
      assertNotNull(unprojectedParams, "missing sample request for " + method.name());

      Map<String, Object> fullResponse =
          (Map<String, Object>) registry.dispatch(method.name(), unprojectedParams);

      String chosenField =
          method.fields().stream()
              .filter(f -> !f.contains(".") && !method.identityFields().contains(f))
              .sorted()
              .findFirst()
              .orElse(method.identityFields().getFirst());

      Map<String, Object> projectedParams = new LinkedHashMap<>(unprojectedParams);
      projectedParams.put("projection", Map.of("fields", List.of(chosenField)));
      Map<String, Object> projectedResponse =
          (Map<String, Object>) registry.dispatch(method.name(), projectedParams);

      Set<String> expectedKeys = new LinkedHashSet<>(method.identityFields());
      expectedKeys.add(chosenField);

      if (fullResponse.containsKey("items")) {
        assertEquals(fullResponse.get("next_cursor") != null, projectedResponse.get("next_cursor") != null);
        assertEquals(fullResponse.get("scan"), projectedResponse.get("scan"));
        List<Map<String, Object>> fullItems = (List<Map<String, Object>>) fullResponse.get("items");
        List<Map<String, Object>> projItems =
            (List<Map<String, Object>>) projectedResponse.get("items");
        assertEquals(fullItems.size(), projItems.size(), method.name());
        for (int i = 0; i < fullItems.size(); i++) {
          Map<String, Object> expectedItem = new LinkedHashMap<>();
          for (String key : expectedKeys) {
            if (fullItems.get(i).containsKey(key)) {
              expectedItem.put(key, fullItems.get(i).get(key));
            }
          }
          assertEquals(expectedItem, projItems.get(i), method.name());
        }
      } else {
        Map<String, Object> expectedResource = new LinkedHashMap<>();
        for (String key : expectedKeys) {
          if (fullResponse.containsKey(key)) {
            expectedResource.put(key, fullResponse.get(key));
          }
        }
        assertEquals(expectedResource, projectedResponse, method.name());
      }
    }

    // Verify nested dot-path projections end-to-end across function.get, function.list, data_type.get, data_type.list, memory.read.
    Map<String, Object> fnDot =
        (Map<String, Object>)
            registry.dispatch(
                "function.get",
                Map.of(
                    "selector",
                    Map.of("entry", "0x00101000"),
                    "projection",
                    Map.of(
                        "fields",
                        List.of("body.start", "parameters.name", "local_variables.storage"))));
    assertEquals(
        Map.of(
            "entry",
            "0x00101000",
            "body",
            Map.of("start", "0x00101000"),
            "parameters",
            List.of(Map.of("name", "argc")),
            "local_variables",
            List.of(Map.of("storage", Map.of("kind", "register", "register", "RAX")))),
        fnDot);

    // Parent + child in both orders returns full body object.
    for (List<String> fields :
        List.of(List.of("body", "body.start"), List.of("body.start", "body"))) {
      Map<String, Object> fnParentChild =
          (Map<String, Object>)
              registry.dispatch(
                  "function.get",
                  Map.of(
                      "selector",
                      Map.of("entry", "0x00101000"),
                      "projection",
                      Map.of("fields", fields)));
      assertEquals(
          Map.of(
              "entry",
              "0x00101000",
              "body",
              Map.of("start", "0x00101000", "end", "0x00101020", "num_addresses", 33L)),
          fnParentChild);
    }

    Map<String, Object> dtDot =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.get",
                Map.of(
                    "selector",
                    Map.of("path", "/Callback"),
                    "projection",
                    Map.of("fields", List.of("signature.return_type"))));
    assertEquals(
        Map.of(
            "path",
            "/Callback",
            "signature",
            Map.of("return_type", Map.of("kind", "named", "name", "int"))),
        dtDot);

    Map<String, Object> memDot =
        (Map<String, Object>)
            registry.dispatch(
                "memory.read",
                Map.of(
                    "selector",
                    Map.of("address", "0x00101000"),
                    "projection",
                    Map.of("fields", List.of("bytes.data"))));
    assertEquals(Map.of("address", "0x00101000", "bytes", Map.of("data", "90c3")), memDot);

    // Verify code_unit.list rejects unselectable value/representation and omits them when unprojected.
    Map<String, Object> unprojectedCodeUnits =
        (Map<String, Object>) registry.dispatch("code_unit.list", Map.of());
    List<Map<String, Object>> cuItems =
        (List<Map<String, Object>>) unprojectedCodeUnits.get("items");
    assertFalse(cuItems.getFirst().containsKey("value"));
    assertFalse(cuItems.getFirst().containsKey("representation"));

    for (String forbidden : List.of("value", "representation")) {
      ApiException err =
          assertThrows(
              ApiException.class,
              () ->
                  registry.dispatch(
                      "code_unit.list",
                      Map.of("projection", Map.of("fields", List.of(forbidden)))));
      assertEquals(400, err.status());
      assertEquals("invalid_enum", err.error().code());

      ApiException decodedErr =
          assertThrows(
              ApiException.class,
              () ->
                  registry
                      .method("code_unit.list")
                      .invokeDecoded(Map.of("fields", List.of(forbidden))));
      assertEquals(400, decodedErr.status());
      assertEquals("unknown_field", decodedErr.error().code());
    }

    // Verify cursor resume works identically under projection.
    Map<String, Object> page1 =
        (Map<String, Object>)
            registry.dispatch(
                "symbol.list",
                Map.of("page", Map.of("limit", 1), "projection", Map.of("fields", List.of("name"))));
    String cursor = (String) page1.get("next_cursor");
    assertNotNull(cursor);
    Map<String, Object> page2 =
        (Map<String, Object>)
            registry.dispatch(
                "symbol.list",
                Map.of(
                    "page",
                    Map.of("limit", 1, "cursor", cursor),
                    "projection",
                    Map.of("fields", List.of("name"))));
    List<Map<String, Object>> page2Items = (List<Map<String, Object>>) page2.get("items");
    assertEquals(List.of(Map.of("address", "0x00101004", "id", "2", "name", "helper")), page2Items);
  }

  private static boolean isReadOnly(ApiMethod<?, ?> method) {
    return method.effects().readOnly();
  }

  private static Map<String, Map<String, Object>> sampleRequests() {
    Map<String, Map<String, Object>> requests = new LinkedHashMap<>();
    requests.put("session.get", Map.of());
    requests.put("program.get", Map.of());
    requests.put("program_language.get", Map.of());
    requests.put("address_space.list", Map.of());
    requests.put("address.resolve", Map.of("selector", Map.of("address", "0x00101000")));
    requests.put("memory_block.get", Map.of("selector", Map.of("name", ".text")));
    requests.put("memory_block.list", Map.of());
    requests.put("memory.read", Map.of("selector", Map.of("address", "0x00101000")));
    requests.put("code_unit.list", Map.of());
    requests.put("data_unit.list", Map.of());
    requests.put("global_variable.get", Map.of("selector", Map.of("address", "0x00200000")));
    requests.put("global_variable.list", Map.of());
    requests.put("instruction.get", Map.of("selector", Map.of("address", "0x00101000")));
    requests.put("instruction.list", Map.of());
    requests.put(
        "flow_override.list",
        Map.of(
            "filter",
            Map.of("selector", Map.of("kind", "address", "address", "0x00101000"))));
    requests.put("function.get", Map.of("selector", Map.of("entry", "0x00101000")));
    requests.put("function.list", Map.of());
    requests.put("function_call.list", Map.of("filter", Map.of("entry", "0x00101000")));
    requests.put("analysis.get", Map.of());
    requests.put("decompilation.get", Map.of("selector", Map.of("entry", "0x00101000")));
    requests.put("symbol.get", Map.of("selector", Map.of("id", "1")));
    requests.put("symbol.list", Map.of("page", Map.of("limit", 1)));
    requests.put("reference.list", Map.of("filter", Map.of("direction", "from")));
    requests.put(
        "comment.get",
        Map.of("selector", Map.of("address", "0x00101000", "type", "eol")));
    requests.put("comment.list", Map.of());
    requests.put("data_type_category.list", Map.of());
    requests.put("data_type.get", Map.of("selector", Map.of("path", "/Callback")));
    requests.put("data_type.list", Map.of());
    return requests;
  }

  private static ApiRegistry buildTestRegistry() {
    ScanProgress scan =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            "0x00101000",
            "0x00102000",
            "0x00101000",
            "0x00101020",
            true,
            ScanProgress.StopReason.COMPLETED,
            2L);

    ProgramService programService =
        proxy(
            ProgramService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getProgram" ->
                      new ProgramResource(
                          "sample.bin",
                          "/bin/sample",
                          "ELF",
                          "0x00100000",
                          "0x00100000",
                          "0x002000ff",
                          "x86:LE:64:default",
                          "gcc",
                          Instant.parse("2026-01-01T00:00:00Z"),
                          Instant.parse("2026-01-02T00:00:00Z"),
                          12L,
                          34L);
                  case "getLanguageInfo" ->
                      new ProgramLanguageResource(
                          "x86:LE:64:default",
                          "gcc",
                          "x86",
                          ProgramLanguageResource.Endian.LITTLE,
                          64);
                  case "getAddressSpaces" ->
                      Page.of(
                          List.of(
                              new AddressSpaceResource(
                                  "ram",
                                  AddressSpaceResource.Kind.RAM,
                                  64,
                                  "0x00000000",
                                  "0xffffffff",
                                  true)),
                          100,
                          null);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    AddressService addressService =
        proxy(
            AddressService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "resolveAddress" ->
                      new AddressResource(
                          "0x00101000",
                          true,
                          true,
                          new AddressResource.MemoryBlockSummary(
                              ".text", "0x00101000", "0x00101fff", 4096L, true, false, true),
                          new AddressResource.FunctionSummary("0x00101000", "main"),
                          new AddressResource.SymbolSummary("1", "main", "Function"),
                          new AddressResource.CodeUnitSummary("0x00101000", "0x00101001"));
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    CommentService commentService =
        proxy(
            CommentService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "listComments" ->
                      Page.scanned(
                          List.of(
                              new CommentResource(
                                  "0x00101000", CommentResource.Type.EOL, "entry comment")),
                          100,
                          null,
                          scan);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    ReferenceService referenceService =
        (fromRaw, toRaw, type, direction, limit, cursor) ->
            Page.of(
                List.of(
                    new ReferenceResource(
                        "0x00101000", "0x00101020", "unconditional_call", 0, true, "analysis")),
                limit,
                null);

    MemoryService memoryService =
        proxy(
            MemoryService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getMemoryBlockByName" ->
                      new MemoryBlockResource(
                          ".text",
                          "0x00101000",
                          "0x00101fff",
                          4096L,
                          true,
                          false,
                          true,
                          true,
                          false,
                          false,
                          MemoryBlockResource.Kind.DEFAULT,
                          "code");
                  case "listMemoryBlocks" ->
                      Page.of(
                          List.of(
                              new MemoryBlockResource(
                                  ".text",
                                  "0x00101000",
                                  "0x00101fff",
                                  4096L,
                                  true,
                                  false,
                                  true,
                                  true,
                                  false,
                                  false,
                                  MemoryBlockResource.Kind.DEFAULT,
                                  "code")),
                          100,
                          null);
                  case "readMemoryRange" ->
                      new MemoryResource(
                          "0x00101000",
                          new ByteSequence(ByteSequence.Encoding.HEX, "90c3", 2));
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    ListingService listingService =
        proxy(
            ListingService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "listCodeUnits" ->
                      Page.scanned(
                          List.of(
                              new CodeUnitResource(
                                  "0x00101000",
                                  CodeUnitResource.Kind.DATA,
                                  4,
                                  new ByteSequence(ByteSequence.Encoding.HEX, "01000000", 4),
                                  "dd 1h",
                                  "dd",
                                  List.of("1h"),
                                  DataTypeReference.named("int"))),
                          100,
                          null,
                          scan);
                  case "listDataUnits" ->
                      Page.scanned(
                          List.of(
                              new DataUnitResource(
                                  "0x00200000",
                                  4,
                                  DataTypeReference.named("int"),
                                  "0x1",
                                  "1h",
                                  new ByteSequence(ByteSequence.Encoding.HEX, "01000000", 4))),
                          100,
                          null,
                          scan);
                  case "getInstruction" ->
                      new InstructionResource(
                          "0x00101000",
                          1,
                          new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                          "NOP",
                          List.of(),
                          FlowOverrideValue.NONE,
                          "fall_through",
                          "fall_through",
                          "0x00101001");
                  case "listInstructions", "getFlowOverrides" ->
                      Page.scanned(
                          List.of(
                              new InstructionResource(
                                  "0x00101000",
                                  1,
                                  new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                                  "NOP",
                                  List.of(),
                                  FlowOverrideValue.BRANCH,
                                  "fall_through",
                                  "unconditional_jump",
                                  null)),
                          100,
                          null,
                          scan);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    FunctionResource sampleFunction =
        new FunctionResource(
            "0x00101000",
            "main",
            "Global",
            new FunctionResource.Body("0x00101000", "0x00101020", 33L),
            "int main(int argc)",
            DataTypeReference.named("int"),
            new VariableStorageReference.Register("EAX"),
            1,
            "__stdcall",
            List.of(
                new FunctionResource.ParameterResource(
                    0,
                    "argc",
                    DataTypeReference.named("int"),
                    new VariableStorageReference.Register("EDI"))),
            List.of(
                new FunctionResource.LocalVariableResource(
                    "local_8",
                    DataTypeReference.named("int"),
                    new VariableStorageReference.Register("RAX"))),
            "entry fn",
            false,
            false,
            false,
            false,
            0,
            false,
            false,
            "rep",
            List.of("entry"),
            null);

    FunctionService functionService =
        proxy(
            FunctionService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getFunction" -> sampleFunction;
                  case "listFunctions" -> Page.scanned(List.of(sampleFunction), 100, null, scan);
                  case "getCallers", "getCallees" ->
                      Page.of(
                          List.of(
                              new FunctionCallResource(
                                  "0x00101040",
                                  "helper",
                                  null,
                                  FunctionCallResource.Direction.CALLEES,
                                  "Global",
                                  null)),
                          100,
                          null);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    GlobalVariableResource sampleGlobal =
        new GlobalVariableResource(
            "0x00200000",
            "g_count",
            "Global",
            DataTypeReference.named("int"),
            4,
            "0x2a",
            "42",
            "user_defined");

    GlobalVariableService globalVariableService =
        proxy(
            GlobalVariableService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getGlobalVariable" -> sampleGlobal;
                  case "listGlobalVariables" ->
                      Page.scanned(List.of(sampleGlobal), 100, null, scan);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getStatus" ->
                      new AnalysisResource(
                          AnalysisResource.Kind.GHIDRA,
                          AnalysisResource.Status.IDLE,
                          true,
                          null,
                          null,
                          null,
                          100.0);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    DecompilationService decompilationService =
        proxy(
            DecompilationService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "decompileFunction" ->
                      new DecompilationResource(
                          "0x00101000",
                          "main",
                          DecompilationResource.Format.TEXT,
                          true,
                          5L,
                          "int main(void) { return 0; }\n",
                          null,
                          null,
                          null,
                          null,
                          List.of());
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    List<SymbolResource> allSymbols =
        List.of(
            new SymbolResource(
                "1", "main", "0x00101000", "Global", "function", "user_defined", true, null),
            new SymbolResource(
                "2", "helper", "0x00101004", "Global", "function", "user_defined", true, null));

    SymbolService symbolService =
        proxy(
            SymbolService.class,
            (proxy, method, args) -> {
              if ("getSymbol".equals(method.getName())) {
                return allSymbols.getFirst();
              }
              if ("listSymbols".equals(method.getName())) {
                SymbolService.SymbolQuery query = (SymbolService.SymbolQuery) args[0];
                List<SymbolResource> filtered = new ArrayList<>();
                for (SymbolResource sym : allSymbols) {
                  if (query.cursor() != null && sym.address().compareTo(query.cursor()) <= 0) {
                    continue;
                  }
                  filtered.add(sym);
                }
                List<SymbolResource> items =
                    filtered.subList(0, Math.min(query.limit(), filtered.size()));
                String next =
                    filtered.size() > query.limit() ? items.getLast().address() : null;
                return Page.scanned(
                    items,
                    query.limit(),
                    next,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        null,
                        null,
                        "0x00101000",
                        items.getLast().address(),
                        next == null,
                        next == null
                            ? ScanProgress.StopReason.COMPLETED
                            : ScanProgress.StopReason.LIMIT,
                        1L));
              }
              return invokeDefaultOrFail(proxy, method, args);
            });

    DataTypeResource callbackDataType =
        new DataTypeResource(
            "/Callback",
            "Callback",
            "/",
            DataTypeResource.Kind.FUNCTION,
            8,
            "void callback",
            8,
            null,
            null,
            new FunctionSignature(
                DataTypeReference.named("int"),
                List.of(new FunctionSignature.Parameter("x", DataTypeReference.named("int"))),
                "__cdecl",
                false,
                false),
            null);

    DataTypeService dataTypeService =
        proxy(
            DataTypeService.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "listCategories" ->
                      Page.of(
                          List.of(new DataTypeCategoryResource("/types", "types", 1, 3)),
                          100,
                          null);
                  case "getDataType" -> callbackDataType;
                  case "searchDataTypes" -> Page.of(List.of(callbackDataType), 100, null);
                  default -> invokeDefaultOrFail(proxy, method, args);
                });

    TransactionRunner txRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException runtime) {
              throw runtime;
            } catch (Exception checked) {
              throw new IllegalStateException(checked);
            }
          }
        };

    BridgeServices services =
        new BridgeServices(
            programService,
            addressService,
            commentService,
            referenceService,
            memoryService,
            listingService,
            functionService,
            globalVariableService,
            analysisService,
            decompilationService,
            symbolService,
            dataTypeService,
            txRunner,
            "sample.bin");

    return new ApiRegistry(
        services,
        "session-1",
        () -> Map.of("id", "session-1", "status", "ready", "program_name", "sample.bin"),
        () -> {});
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> iface, InvocationHandler handler) {
    return (T)
        Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[] {iface},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> iface.getSimpleName() + "Proxy";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(proxy, method, args);
            });
  }

  private static Object invokeDefaultOrFail(
      Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
    if (method.isDefault()) {
      return InvocationHandler.invokeDefault(proxy, method, args);
    }
    throw new UnsupportedOperationException("unexpected service call: " + method);
  }
}
