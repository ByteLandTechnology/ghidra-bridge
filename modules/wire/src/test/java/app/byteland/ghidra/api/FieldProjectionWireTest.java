package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
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
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedClass;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.Test;

class FieldProjectionWireTest {

  @Test
  void apiMethodValidatesProjectionFieldsOnceAndPreservesErrorCodes() throws Exception {
    TestFixture fixture = new TestFixture();
    ApiMethod<Map<String, Object>, Object> method = fixture.registry.method("symbol.get");

    CountingFieldList requested = new CountingFieldList(List.of("name", "namespace"));
    Object result =
        method.invokeDecoded(Map.of("selector", Map.of("id", "7"), "fields", requested));
    assertEquals(Map.of("id", "7", "name", "sym_7", "namespace", "Global"), result);
    assertEquals(1, requested.sizeCalls.get());
    assertEquals(2, requested.getCalls.get());

    // Check that PreparedDispatch checks projection once and returns projected output.
    ApiRegistry.PreparedDispatch prepared =
        fixture.registry.prepareDispatch(
            "symbol.get",
            Map.of(
                "selector",
                Map.of("id", "7"),
                "projection",
                Map.of("fields", List.of("name"))));
    Object rawPrepared = prepared.execute();
    assertEquals(Map.of("id", "7", "name", "sym_7"), prepared.encodeResponse(rawPrepared));

    // Direct ApiMethod instances with a plain Handler also project and validate in one pass.
    Map<String, Object> flatInput =
        ApiSchemaCatalog.input(ApiSchemaCatalog.props("fields", ApiRegistry.fieldsSchema()));
    ApiMethod<Map<String, Object>, Object> customRead =
        new ApiMethod<>(
            "custom.get",
            "Read a custom record.",
            ApiMethod.MethodEffects.readOnlyMethod(),
            new StrictObjectCodec(StrictObjectCodec.canonicalSchema(flatInput), flatInput),
            new JsonValueCodec(
                ApiSchemaCatalog.resourceSchema(Set.of("id", "name", "type"), List.of("id"))),
            Set.of("id", "name", "type"),
            List.of("id"),
            req -> Map.of("id", "1", "name", "alpha", "type", "label"));
    assertEquals(
        Map.of("id", "1", "name", "alpha"),
        customRead.invokeDecoded(
            customRead.decodeRequest(Map.of("projection", Map.of("fields", List.of("name"))))));

    // Non-list fields, invalid paths, duplicates, and unknown fields return 400 errors.
    ApiException nonArray =
        assertThrows(
            ApiException.class,
            () -> method.invokeDecoded(Map.of("selector", Map.of("id", "7"), "fields", "name")));
    assertEquals(400, nonArray.status());
    assertEquals("invalid_fields", nonArray.error().code());
    assertEquals("/projection/fields", nonArray.error().target());

    for (String badPath : List.of("   ", "name*", ".name", "name.", "a..b", "0", "items.0.name")) {
      ApiException invalidPath =
          assertThrows(
              ApiException.class,
              () ->
                  method.invokeDecoded(
                      Map.of("selector", Map.of("id", "7"), "fields", List.of(badPath))));
      assertEquals(400, invalidPath.status());
      assertEquals("invalid_fields", invalidPath.error().code());
      assertEquals("/projection/fields/0", invalidPath.error().target());
    }

    ApiException duplicate =
        assertThrows(
            ApiException.class,
            () ->
                fixture.registry.dispatch(
                    "symbol.get",
                    Map.of(
                        "selector",
                        Map.of("id", "7"),
                        "projection",
                        Map.of("fields", List.of("name", "name")))));
    assertEquals(400, duplicate.status());
    assertEquals("duplicate_field", duplicate.error().code());
    assertEquals("/projection/fields/1", duplicate.error().target());

    ApiException unknown =
        assertThrows(
            ApiException.class,
            () ->
                method.invokeDecoded(
                    Map.of("selector", Map.of("id", "7"), "fields", List.of("not_a_field"))));
    assertEquals(400, unknown.status());
    assertEquals("unknown_field", unknown.error().code());
    assertEquals("/projection/fields/0", unknown.error().target());
  }

  @Test
  void wireValuesReflectsOnlySelectedRecordComponentsAndDotPaths() {
    AtomicInteger selectedCalls = new AtomicInteger();
    GuardedNested nested = new GuardedNested("0x00401000", selectedCalls);
    GuardedChild childOne = new GuardedChild("arg0", selectedCalls);
    GuardedChild childTwo = new GuardedChild("arg1", selectedCalls);
    GuardedRoot root = new GuardedRoot("fn_1", nested, List.of(childOne, childTwo), selectedCalls);

    Set<String> selected =
        new LinkedHashSet<>(List.of("id", "nested.keep", "children.label"));
    Map<String, Object> projected = WireValues.resource(root, selected);
    assertEquals(
        Map.of(
            "id",
            "fn_1",
            "nested",
            Map.of("keep", "0x00401000"),
            "children",
            List.of(Map.of("label", "arg0"), Map.of("label", "arg1"))),
        projected);
    // Accessor calls: id(1) + nested(1) + nested.keep(1) + children(1) + 2 * label(2) = 6.
    assertEquals(6, selectedCalls.get());

    // List pages reuse the per-record projection plan and keep scan and next_cursor unchanged.
    selectedCalls.set(0);
    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            "0x1000",
            "0x2000",
            "0x1000",
            "0x1010",
            false,
            ScanProgress.StopReason.LIMIT,
            3L);
    Page<GuardedRoot> page = Page.scanned(List.of(root, root), 2, "0x1020", progress);
    Map<String, Object> projectedList =
        WireValues.list(page, new LinkedHashSet<>(List.of("id", "nested.keep")));
    assertEquals(
        List.of(
            Map.of("id", "fn_1", "nested", Map.of("keep", "0x00401000")),
            Map.of("id", "fn_1", "nested", Map.of("keep", "0x00401000"))),
        projectedList.get("items"));
    assertEquals("0x1020", projectedList.get("next_cursor"));
    assertNotNull(projectedList.get("scan"));
    assertEquals(6, selectedCalls.get());

    // Parent and child paths together emit the full parent object at its first key slot.
    FunctionResource.Body body = new FunctionResource.Body("0x1000", "0x1020", 32L);
    Map<String, Object> bodyParentFirst =
        WireValues.resource(
            Map.of("entry", "0x1000", "body", body, "name", "fn"),
            new LinkedHashSet<>(List.of("entry", "body", "body.start", "name")));
    Map<String, Object> bodyChildFirst =
        WireValues.resource(
            Map.of("entry", "0x1000", "body", body, "name", "fn"),
            new LinkedHashSet<>(List.of("entry", "body.start", "name", "body")));
    assertEquals(
        Map.of("start", "0x1000", "end", "0x1020", "num_addresses", 32L),
        bodyParentFirst.get("body"));
    assertEquals(bodyParentFirst, bodyChildFirst);
    assertEquals(List.of("entry", "body", "name"), List.copyOf(bodyChildFirst.keySet()));

    // Sealed DataTypeReference and VariableStorageReference allow nested projections.
    DataTypeReference pointerType =
        DataTypeReference.pointerTo(DataTypeReference.named("/uint32_t"));
    assertEquals(
        Map.of("target", Map.of("name", "/uint32_t")),
        WireValues.normalize(pointerType, Set.of("target.name")));
    assertEquals(
        Map.of("register", "RCX"),
        WireValues.normalize(VariableStorageReference.register("RCX"), Set.of("register")));
  }

  @Test
  void projectedSchemasValidateInOnePassAndCachePerFieldSet() throws Exception {
    Map<String, Object> functionSchema =
        ApiSchemaCatalog.scanListSchema(ApiSchemaCatalog.functionFields(), List.of("entry"));
    JsonValueCodec functionCodec = new JsonValueCodec(functionSchema);

    Set<String> dotProjection =
        new LinkedHashSet<>(
            List.of("entry", "body.start", "parameters.name", "local_variables.storage"));
    Map<String, Object> firstDerived = functionCodec.projectedSchema(dotProjection);
    Map<String, Object> secondDerived =
        functionCodec.projectedSchema(new LinkedHashSet<>(dotProjection));
    assertSame(firstDerived, secondDerived);

    Map<String, Object> validProjectedPayload =
        Map.of(
            "items",
            List.of(
                Map.of(
                    "entry",
                    "ram:00401000",
                    "body",
                    Map.of("start", "ram:00401000"),
                    "parameters",
                    List.of(Map.of("name", "argc")),
                    "local_variables",
                    List.of(Map.of("storage", Map.of("kind", "register", "register", "RAX"))))));

    // Check that projected schema validation throws zero internal ApiException instances.
    Path recordingPath = Files.createTempFile("projected-schema-test-", ".jfr");
    try {
      try (Recording recording = new Recording()) {
        recording.enable("jdk.JavaExceptionThrow").withoutThreshold();
        recording.start();
        for (int index = 0; index < 25; index++) {
          assertSame(validProjectedPayload, functionCodec.encode(validProjectedPayload, dotProjection));
        }
        recording.stop();
        recording.dump(recordingPath);
      }
      long thrownApiExceptions = 0;
      try (RecordingFile file = new RecordingFile(recordingPath)) {
        while (file.hasMoreEvents()) {
          RecordedEvent event = file.readEvent();
          if ("jdk.JavaExceptionThrow".equals(event.getEventType().getName())) {
            RecordedClass thrownClass = event.getValue("thrownClass");
            if (thrownClass != null
                && ApiException.class.getName().equals(thrownClass.getName())) {
              thrownApiExceptions++;
            }
          }
        }
      }
      assertEquals(0L, thrownApiExceptions);
    } finally {
      Files.deleteIfExists(recordingPath);
    }

    // Unselected properties and invalid selected field types return 500 invalid_response.
    Map<String, Object> leakedSibling =
        Map.of(
            "items",
            List.of(
                Map.of(
                    "entry",
                    "ram:00401000",
                    "body",
                    Map.of("start", "ram:00401000", "end", "ram:00401010"))));
    ApiException leakedError =
        assertThrows(
            ApiException.class, () -> functionCodec.encode(leakedSibling, dotProjection));
    assertEquals(500, leakedError.status());
    assertEquals("invalid_response", leakedError.error().code());
    assertEquals("/result/items/0/body/end", leakedError.error().target());

    Map<String, Object> wrongSelectedType =
        Map.of(
            "items",
            List.of(Map.of("entry", "ram:00401000", "body", Map.of("start", 12345))));
    ApiException typeError =
        assertThrows(
            ApiException.class, () -> functionCodec.encode(wrongSelectedType, dotProjection));
    assertEquals(500, typeError.status());
    assertEquals("invalid_response", typeError.error().code());
    assertEquals("/result/items/0/body/start", typeError.error().target());

    // Multi-object union schemas validate projected branches when discriminators are absent.
    Map<String, Object> typeEnvelopeSchema =
        WireSchema.withDefinitions(
            WireSchema.object(Map.of("data_type", WireSchema.dataTypeReference()), "data_type"));
    Map<String, Object> projectedTypeSchema =
        WireSchema.project(typeEnvelopeSchema, Set.of("data_type.name"));
    assertDoesNotThrow(
        () ->
            WireSchema.validate(
                Map.of("data_type", Map.of("name", "int")), projectedTypeSchema, "/result"));
    assertDoesNotThrow(
        () -> WireSchema.validate(Map.of("data_type", Map.of()), projectedTypeSchema, "/result"));
    ApiException invalidBlankName =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of("data_type", Map.of("name", "")), projectedTypeSchema, "/result"));
    assertEquals("invalid_union", invalidBlankName.error().code());
  }

  @Test
  @SuppressWarnings("unchecked")
  void allTwentyNineProjectionMethodsReturnIdenticalProjectedPayloadsAndCursors()
      throws Exception {
    TestFixture fixture = new TestFixture();
    ApiCatalog catalog = fixture.registry.methodCatalog();

    List<String> projectionMethods =
        catalog.methods().stream()
            .filter(
                descriptor -> {
                  Object props = descriptor.inputSchema().get("properties");
                  return props instanceof Map<?, ?> map && map.containsKey("projection");
                })
            .map(ApiCatalog.MethodDescriptor::name)
            .toList();
    assertEquals(29, projectionMethods.size());

    List<MethodCase> cases = fixture.allProjectionCases();
    assertEquals(
        Set.copyOf(projectionMethods),
        cases.stream().map(MethodCase::method).collect(java.util.stream.Collectors.toSet()));

    for (MethodCase testCase : cases) {
      ApiMethod<Map<String, Object>, Object> apiMethod =
          fixture.registry.method(testCase.method());
      Map<String, Object> unprojected =
          (Map<String, Object>)
              fixture.registry.dispatch(testCase.method(), testCase.baseParams());
      Map<String, Object> projectedParams = new LinkedHashMap<>(testCase.baseParams());
      projectedParams.put("projection", Map.of("fields", testCase.projectedFields()));
      Map<String, Object> projected =
          (Map<String, Object>) fixture.registry.dispatch(testCase.method(), projectedParams);

      Set<String> expectedSelected = new LinkedHashSet<>(apiMethod.identityFields());
      expectedSelected.addAll(testCase.projectedFields());
      Map<String, Object> expected = referenceProject(unprojected, expectedSelected);
      assertEquals(expected, projected, "Mismatch on method " + testCase.method());
    }

    // Check that requestedIncludes skips omitted parameters and locals and loads dot-paths.
    fixture.lastIncludes.set(null);
    fixture.registry.dispatch(
        "function.get",
        Map.of(
            "selector",
            Map.of("entry", "ram:00401000"),
            "projection",
            Map.of("fields", List.of("body.start"))));
    assertEquals(Set.of(), fixture.lastIncludes.get());

    fixture.registry.dispatch(
        "function.list",
        Map.of("projection", Map.of("fields", List.of("parameters.name"))));
    assertEquals(Set.of("parameters"), fixture.lastIncludes.get());

    fixture.registry.dispatch(
        "function.list",
        Map.of("projection", Map.of("fields", List.of("local_variables.storage"))));
    assertEquals(Set.of("locals"), fixture.lastIncludes.get());

    // Check page order, identityFields, and cursor continuity across projected pages.
    Map<String, Object> firstProjectedPage =
        (Map<String, Object>)
            fixture.registry.dispatch(
                "symbol.list",
                Map.of(
                    "page",
                    Map.of("limit", 2),
                    "projection",
                    Map.of("fields", List.of("name"))));
    List<Map<String, Object>> symbolItems =
        (List<Map<String, Object>>) firstProjectedPage.get("items");
    assertEquals(
        List.of(
            Map.of("address", "ram:00401000", "id", "2", "name", "sym_2"),
            Map.of("address", "ram:00401000", "id", "1", "name", "sym_1")),
        symbolItems);
    String nextCursor = (String) firstProjectedPage.get("next_cursor");
    assertNotNull(nextCursor);
    assertNotNull(firstProjectedPage.get("scan"));

    // Next cursor from a projected call decodes on the next page with a different projection.
    Map<String, Object> secondProjectedPage =
        (Map<String, Object>)
            fixture.registry.dispatch(
                "symbol.list",
                Map.of(
                    "page",
                    Map.of("limit", 2, "cursor", nextCursor),
                    "projection",
                    Map.of("fields", List.of("type"))));
    assertEquals("ram:00401008", fixture.lastSymbolCursor.get());
    assertEquals(
        List.of(
            Map.of("address", "ram:00401000", "id", "2", "type", "function"),
            Map.of("address", "ram:00401000", "id", "1", "type", "function")),
        secondProjectedPage.get("items"));

    // Check that batch.execute accepts projected read and list items.
    Map<String, Object> batchResult =
        (Map<String, Object>)
            fixture.registry.dispatch(
                "batch.execute",
                Map.of(
                    "items",
                    List.of(
                        Map.of(
                            "id",
                            "m1",
                            "method",
                            "memory.read",
                            "arguments",
                            Map.of(
                                "selector",
                                Map.of("address", "ram:00401000"),
                                "projection",
                                Map.of("fields", List.of("bytes.length")))),
                        Map.of(
                            "id",
                            "d1",
                            "method",
                            "data_type.get",
                            "arguments",
                            Map.of(
                                "selector",
                                Map.of("path", "/FuncSig"),
                                "projection",
                                Map.of("fields", List.of("signature.return_type")))))));
    List<Map<String, Object>> batchRows = (List<Map<String, Object>>) batchResult.get("items");
    assertEquals(
        Map.of("address", "ram:00401000", "bytes", Map.of("length", 4)),
        batchRows.get(0).get("result"));
    assertEquals(
        Map.of(
            "path",
            "/FuncSig",
            "signature",
            Map.of("return_type", Map.of("kind", "named", "name", "/int"))),
        batchRows.get(1).get("result"));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> referenceProject(
      Map<String, Object> unprojected, Set<String> selected) {
    if (unprojected.get("items") instanceof List<?> items && !selected.contains("items")) {
      Map<String, Object> copy = new LinkedHashMap<>(unprojected);
      List<Map<String, Object>> projectedItems = new ArrayList<>(items.size());
      for (Object item : items) {
        projectedItems.add(referenceProjectMap((Map<String, Object>) item, selected));
      }
      copy.put("items", projectedItems);
      return copy;
    }
    return referenceProjectMap(unprojected, selected);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> referenceProjectMap(
      Map<String, Object> source, Set<String> selected) {
    Map<String, Object> target = new LinkedHashMap<>();
    for (String path : selected) {
      copyReferencePath(source, target, path, 0);
    }
    return target;
  }

  @SuppressWarnings("unchecked")
  private static void copyReferencePath(
      Map<String, Object> source, Map<String, Object> target, String path, int start) {
    int dot = path.indexOf('.', start);
    String segment = dot < 0 ? path.substring(start) : path.substring(start, dot);
    Object value = source.get(segment);
    if (value == null) {
      return;
    }
    if (dot < 0) {
      target.put(segment, value);
      return;
    }
    if (value instanceof Map<?, ?> child) {
      Map<String, Object> targetChild =
          (Map<String, Object>) target.computeIfAbsent(segment, ignored -> new LinkedHashMap<>());
      copyReferencePath((Map<String, Object>) child, targetChild, path, dot + 1);
    } else if (value instanceof List<?> list) {
      List<Map<String, Object>> targetList =
          target.get(segment) instanceof List<?> existing
              ? (List<Map<String, Object>>) existing
              : new ArrayList<>();
      for (int index = 0; index < list.size(); index++) {
        Map<String, Object> item = (Map<String, Object>) list.get(index);
        Map<String, Object> targetChild;
        if (index < targetList.size()) {
          targetChild = targetList.get(index);
        } else {
          targetChild = new LinkedHashMap<>();
          targetList.add(targetChild);
        }
        copyReferencePath(item, targetChild, path, dot + 1);
      }
      target.put(segment, targetList);
    }
  }

  private static final class CountingFieldList extends AbstractList<String> {
    private final List<String> delegate;
    private final AtomicInteger sizeCalls = new AtomicInteger();
    private final AtomicInteger getCalls = new AtomicInteger();

    CountingFieldList(List<String> delegate) {
      this.delegate = delegate;
    }

    @Override
    public String get(int index) {
      getCalls.incrementAndGet();
      return delegate.get(index);
    }

    @Override
    public int size() {
      sizeCalls.incrementAndGet();
      return delegate.size();
    }
  }

  public record GuardedRoot(
      String id, GuardedNested nested, List<GuardedChild> children, AtomicInteger counter) {
    @Override
    public String id() {
      counter.incrementAndGet();
      return id;
    }

    @Override
    public GuardedNested nested() {
      counter.incrementAndGet();
      return nested;
    }

    @Override
    public List<GuardedChild> children() {
      counter.incrementAndGet();
      return children;
    }

    @Override
    public AtomicInteger counter() {
      throw new AssertionError("unselected root accessor must not be invoked");
    }
  }

  public record GuardedNested(String keep, AtomicInteger counter) {
    @Override
    public String keep() {
      counter.incrementAndGet();
      return keep;
    }

    @Override
    public AtomicInteger counter() {
      throw new AssertionError("unselected nested accessor must not be invoked");
    }
  }

  public record GuardedChild(String label, AtomicInteger counter) {
    @Override
    public String label() {
      counter.incrementAndGet();
      return label;
    }

    @Override
    public AtomicInteger counter() {
      throw new AssertionError("unselected list element accessor must not be invoked");
    }
  }

  private record MethodCase(
      String method, Map<String, Object> baseParams, List<String> projectedFields) {}

  private static final class TestFixture {
    final AtomicReference<Set<String>> lastIncludes = new AtomicReference<>();
    final AtomicReference<String> lastSymbolCursor = new AtomicReference<>();
    final ApiRegistry registry;

    TestFixture() {
      ScanProgress scan =
          new ScanProgress(
              ScanProgress.Kind.ADDRESS,
              "ram:00401000",
              "ram:00402000",
              "ram:00401000",
              "ram:00401004",
              false,
              ScanProgress.StopReason.LIMIT,
              2L);

      ProgramResource program =
          new ProgramResource(
              "sample.bin",
              "/bin/sample",
              "ELF",
              "ram:00400000",
              "ram:00400000",
              "ram:0040ffff",
              "x86:LE:64:default",
              "gcc",
              Instant.parse("2026-06-05T00:00:00Z"),
              Instant.parse("2026-06-05T01:00:00Z"),
              10L,
              25L);
      ProgramLanguageResource language =
          new ProgramLanguageResource(
              "x86:LE:64:default", "gcc", "x86", ProgramLanguageResource.Endian.LITTLE, 64);
      AddressSpaceResource space =
          new AddressSpaceResource(
              "ram", AddressSpaceResource.Kind.RAM, 64, "ram:00000000", "ram:ffffffff", true);

      AddressResource address =
          new AddressResource(
              "ram:00401000",
              true,
              true,
              new AddressResource.MemoryBlockSummary(
                  ".text", "ram:00401000", "ram:00401fff", 4096L, true, false, true),
              new AddressResource.FunctionSummary("ram:00401000", "main"),
              new AddressResource.SymbolSummary("1", "main", "function"),
              new AddressResource.CodeUnitSummary("ram:00401000", "ram:00401003"));

      MemoryBlockResource block =
          new MemoryBlockResource(
              ".text",
              "ram:00401000",
              "ram:00401fff",
              4096L,
              true,
              false,
              true,
              true,
              false,
              false,
              MemoryBlockResource.Kind.DEFAULT,
              "code");
      MemoryResource memory =
          new MemoryResource(
              "ram:00401000", new ByteSequence(ByteSequence.Encoding.HEX, "4889e590", 4));

      CodeUnitResource codeUnit =
          new CodeUnitResource(
              "ram:00401000",
              CodeUnitResource.Kind.INSTRUCTION,
              4,
              new ByteSequence(ByteSequence.Encoding.HEX, "4889e590", 4),
              "MOV RBP, RSP",
              "MOV",
              List.of("RBP", "RSP"),
              null);
      DataUnitResource dataUnit =
          new DataUnitResource(
              "ram:00402000",
              4,
              DataTypeReference.named("/dword"),
              "0x2a",
              "42h",
              new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4));
      InstructionResource instruction =
          new InstructionResource(
              "ram:00401000",
              4,
              new ByteSequence(ByteSequence.Encoding.HEX, "4889e590", 4),
              "MOV",
              List.of("RBP", "RSP"),
              FlowOverrideValue.NONE,
              "fall_through",
              "fall_through",
              "ram:00401004");

      GlobalVariableResource globalVar =
          new GlobalVariableResource(
              "ram:00403000",
              "g_counter",
              "Global",
              DataTypeReference.named("/int"),
              4,
              "1",
              "1",
              "user_defined");

      FunctionResource function =
          new FunctionResource(
              "ram:00401000",
              "main",
              "Global",
              new FunctionResource.Body("ram:00401000", "ram:00401020", 33L),
              "int main(int argc)",
              DataTypeReference.named("/int"),
              VariableStorageReference.register("EAX"),
              1,
              "__cdecl",
              List.of(
                  new FunctionResource.ParameterResource(
                      0,
                      "argc",
                      DataTypeReference.named("/int"),
                      VariableStorageReference.register("EDI"))),
              List.of(
                  new FunctionResource.LocalVariableResource(
                      "local_0",
                      DataTypeReference.named("/int"),
                      VariableStorageReference.serialization("Stack[-0x8]:4"))),
              "entry comment",
              false,
              false,
              false,
              false,
              0,
              false,
              false,
              "repeatable",
              List.of("entry"),
              "main(int)");
      FunctionCallResource call =
          new FunctionCallResource(
              "ram:00401050",
              "helper",
              "ram:00401010",
              FunctionCallResource.Direction.CALLEES,
              "Global",
              "helper()");

      AnalysisResource analysis =
          new AnalysisResource(
              AnalysisResource.Kind.GHIDRA,
              AnalysisResource.Status.IDLE,
              true,
              "task-1",
              Instant.parse("2026-06-05T00:00:00Z"),
              Instant.parse("2026-06-05T00:00:05Z"),
              100.0);

      SymbolResource symTwo =
          new SymbolResource(
              "2", "sym_2", "ram:00401000", "Global", "function", "analysis", false, "sym_2()");
      SymbolResource symOne =
          new SymbolResource(
              "1", "sym_1", "ram:00401000", "Global", "function", "analysis", true, "sym_1()");

      CommentResource comment =
          new CommentResource("ram:00401000", CommentResource.Type.EOL, "setup frame");

      DecompilationResource decompilation =
          new DecompilationResource(
              "ram:00401000",
              "main",
              DecompilationResource.Format.DOCUMENT,
              true,
              15L,
              "int main(int argc) { return argc; }",
              null,
              List.of(
                  new DecompilationResource.Line(
                      1,
                      0,
                      List.of(
                          new DecompilationResource.LocatedToken(
                              DecompilationResource.Token.Kind.FUNCTION,
                              "main",
                              4,
                              8,
                              "ram:00401000",
                              "ram:00401000",
                              "ram:00401000",
                              "ram:00401000",
                              symOne)))),
              List.of(comment),
              true,
              List.of());

      ReferenceResource reference =
          new ReferenceResource(
              "ram:00401010", "ram:00401050", "unconditional_call", 0, true, "analysis");

      DataTypeCategoryResource category = new DataTypeCategoryResource("/types", "types", 1, 3);
      DataTypeResource funcSigType =
          new DataTypeResource(
              "/FuncSig",
              "FuncSig",
              "/",
              DataTypeResource.Kind.FUNCTION,
              0,
              "callback type",
              0,
              null,
              null,
              new FunctionSignature(
                  DataTypeReference.named("/int"),
                  List.of(new FunctionSignature.Parameter("x", DataTypeReference.named("/int"))),
                  "__cdecl",
                  false,
                  false),
              null);

      ProgramService programService =
          proxy(
              ProgramService.class,
              (name, args) ->
                  switch (name) {
                    case "getProgram" -> program;
                    case "getLanguageInfo" -> language;
                    case "getAddressSpaces" -> Page.of(List.of(space), 10, "ram");
                    default -> throw new AssertionError(name);
                  });
      AddressService addressService = proxy(AddressService.class, (name, args) -> address);
      MemoryService memoryService =
          proxy(
              MemoryService.class,
              (name, args) ->
                  switch (name) {
                    case "getMemoryBlockByName" -> block;
                    case "listMemoryBlocks" -> Page.of(List.of(block), 10, ".text");
                    case "readMemoryRange" -> memory;
                    default -> throw new AssertionError(name);
                  });
      ListingService listingService =
          proxy(
              ListingService.class,
              (name, args) ->
                  switch (name) {
                    case "listCodeUnits" ->
                        Page.scanned(List.of(codeUnit), 10, "ram:00401004", scan);
                    case "listDataUnits" ->
                        Page.scanned(List.of(dataUnit), 10, "ram:00402004", scan);
                    case "getInstruction" -> instruction;
                    case "listInstructions", "getFlowOverrides" ->
                        Page.scanned(List.of(instruction), 10, "ram:00401004", scan);
                    default -> throw new AssertionError(name);
                  });
      GlobalVariableService globalVariableService =
          proxy(
              GlobalVariableService.class,
              (name, args) ->
                  switch (name) {
                    case "getGlobalVariable" -> globalVar;
                    case "listGlobalVariables" ->
                        Page.scanned(List.of(globalVar), 10, "ram:00403004", scan);
                    default -> throw new AssertionError(name);
                  });
      FunctionService functionService =
          proxy(
              FunctionService.class,
              (name, args) ->
                  switch (name) {
                    case "getFunction" -> {
                      @SuppressWarnings("unchecked")
                      Set<String> includes = (Set<String>) args[1];
                      lastIncludes.set(includes);
                      yield function;
                    }
                    case "listFunctions" -> {
                      FunctionService.FunctionQuery query = (FunctionService.FunctionQuery) args[0];
                      lastIncludes.set(query.includes());
                      yield Page.scanned(List.of(function), 10, "ram:00401030", scan);
                    }
                    case "getCallees", "getCallers" -> Page.of(List.of(call), 10, "ram:00401050");
                    default -> throw new AssertionError(name);
                  });
      AnalysisService analysisService = proxy(AnalysisService.class, (name, args) -> analysis);
      DecompilationService decompilationService =
          proxy(DecompilationService.class, (name, args) -> decompilation);
      SymbolService symbolService =
          proxy(
              SymbolService.class,
              (name, args) ->
                  switch (name) {
                    case "getSymbol" ->
                        new SymbolResource(
                            String.valueOf(args[0]),
                            "sym_" + args[0],
                            "ram:00401000",
                            "Global",
                            "function",
                            "analysis",
                            true,
                            null);
                    case "listSymbols" -> {
                      SymbolService.SymbolQuery query = (SymbolService.SymbolQuery) args[0];
                      lastSymbolCursor.set(query.cursor());
                      // Keep page order when two symbols share an address.
                      yield Page.scanned(List.of(symTwo, symOne), 2, "ram:00401008", scan);
                    }
                    default -> throw new AssertionError(name);
                  });
      ReferenceService referenceService =
          proxy(
              ReferenceService.class,
              (name, args) -> Page.of(List.of(reference), 10, "ram:00401010"));
      CommentService commentService =
          proxy(
              CommentService.class,
              (name, args) -> Page.scanned(List.of(comment), 10, "ram:00401004", scan));
      DataTypeService dataTypeService =
          proxy(
              DataTypeService.class,
              (name, args) ->
                  switch (name) {
                    case "listCategories" -> Page.of(List.of(category), 10, "/types");
                    case "getDataType" -> funcSigType;
                    case "searchDataTypes" -> Page.of(List.of(funcSigType), 10, "/FuncSig");
                    case "parseCDeclarations" -> List.of(funcSigType);
                    default -> throw new AssertionError(name);
                  });
      TransactionRunner txRunner =
          new TransactionRunner() {
            @Override
            public <T> T run(Operation<T> operation) {
              try {
                return operation.execute();
              } catch (Exception exception) {
                throw new RuntimeException(exception);
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
      this.registry =
          new ApiRegistry(
              services,
              "session-proj",
              () -> Map.of("id", "session-proj", "status", "active", "program_name", "sample.bin"),
              () -> {});
    }

    List<MethodCase> allProjectionCases() {
      return List.of(
          new MethodCase("session.get", Map.of(), List.of("status")),
          new MethodCase("program.get", Map.of(), List.of("image_base", "function_count")),
          new MethodCase("program_language.get", Map.of(), List.of("endian", "address_size")),
          new MethodCase("address_space.list", Map.of(), List.of("default", "size")),
          new MethodCase(
              "address.resolve",
              Map.of("selector", Map.of("address", "ram:00401000")),
              List.of("function", "code_unit")),
          new MethodCase(
              "memory_block.get",
              Map.of("selector", Map.of("name", ".text")),
              List.of("volatile", "execute")),
          new MethodCase("memory_block.list", Map.of(), List.of("start", "length")),
          new MethodCase(
              "memory.read",
              Map.of("selector", Map.of("address", "ram:00401000")),
              List.of("bytes.length")),
          new MethodCase("code_unit.list", Map.of(), List.of("mnemonic")),
          new MethodCase("data_unit.list", Map.of(), List.of("value")),
          new MethodCase(
              "global_variable.get",
              Map.of("selector", Map.of("address", "ram:00403000")),
              List.of("name", "data_type")),
          new MethodCase("global_variable.list", Map.of(), List.of("name")),
          new MethodCase(
              "instruction.get",
              Map.of("selector", Map.of("address", "ram:00401000")),
              List.of("mnemonic", "operands")),
          new MethodCase("instruction.list", Map.of(), List.of("mnemonic")),
          new MethodCase(
              "flow_override.list",
              Map.of(
                  "filter",
                  Map.of("selector", Map.of("kind", "address", "address", "ram:00401000"))),
              List.of("flow_override")),
          new MethodCase(
              "function.get",
              Map.of("selector", Map.of("entry", "ram:00401000")),
              List.of("body.start", "parameters.name", "local_variables.storage")),
          new MethodCase(
              "function.list",
              Map.of(),
              List.of("body.start", "parameters.name")),
          new MethodCase(
              "function_call.list",
              Map.of("filter", Map.of("entry", "ram:00401000")),
              List.of("call_site", "direction")),
          new MethodCase("analysis.get", Map.of(), List.of("status", "progress")),
          new MethodCase(
              "decompilation.get",
              Map.of("selector", Map.of("entry", "ram:00401000"), "format", "document"),
              List.of("c", "lines")),
          new MethodCase(
              "symbol.get",
              Map.of("selector", Map.of("id", "1")),
              List.of("name")),
          new MethodCase("symbol.list", Map.of(), List.of("name")),
          new MethodCase(
              "reference.list",
              Map.of("filter", Map.of("direction", "from", "from", "ram:00401010")),
              List.of("primary")),
          new MethodCase(
              "comment.get",
              Map.of("selector", Map.of("address", "ram:00401000", "type", "eol")),
              List.of("text")),
          new MethodCase("comment.list", Map.of(), List.of("text")),
          new MethodCase("data_type_category.list", Map.of(), List.of("data_type_count")),
          new MethodCase(
              "data_type.get",
              Map.of("selector", Map.of("path", "/FuncSig")),
              List.of("signature.return_type")),
          new MethodCase(
              "data_type.list",
              Map.of(),
              List.of("signature.parameters")),
          new MethodCase(
              "data_type.parse_c",
              Map.of("declarations", "typedef int FuncSig(int x);"),
              List.of("signature.parameters")));
    }

    private interface ServiceCall {
      Object invoke(String name, Object[] args);
    }

    private static <T> T proxy(Class<T> type, ServiceCall handler) {
      return type.cast(
          Proxy.newProxyInstance(
              type.getClassLoader(),
              new Class<?>[] {type},
              (instance, method, args) -> handler.invoke(method.getName(), args)));
    }
  }
}
