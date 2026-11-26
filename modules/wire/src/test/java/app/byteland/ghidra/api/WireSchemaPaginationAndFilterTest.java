package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WireSchemaPaginationAndFilterTest {

  @Test
  void memoryReadRequiresAddressAndSupportsDottedProjections() throws Exception {
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("readMemoryRange", method);
              return new MemoryResource(
                  "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, "9090", 2));
            });
    ApiRegistry registry = registryWith(memory, unused(FunctionService.class),
        unused(DataTypeService.class), unused(SymbolService.class), unused(ReferenceService.class));

    Map<String, Object> outputSchema = registry.method("memory.read").responseCodec().schema();
    assertEquals(List.of("address"), outputSchema.get("required"));
    Map<?, ?> bytesSchema = (Map<?, ?>) ((Map<?, ?>) outputSchema.get("properties")).get("bytes");
    assertEquals(1, bytesSchema.get("minProperties"));
    assertFalse(bytesSchema.containsKey("required"));

    @SuppressWarnings("unchecked")
    Map<String, Object> projected =
        (Map<String, Object>)
            registry.dispatch(
                "memory.read",
                Map.of(
                    "selector", Map.of("address", "ram:00100000"),
                    "projection", Map.of("fields", List.of("bytes.data"))));
    assertEquals(Map.of("address", "ram:00100000", "bytes", Map.of("data", "9090")), projected);

    @SuppressWarnings("unchecked")
    Map<String, Object> unprojected =
        (Map<String, Object>)
            registry.dispatch("memory.read", Map.of("selector", Map.of("address", "ram:00100000")));
    assertEquals("ram:00100000", unprojected.get("address"));
    assertEquals(
        Map.of("encoding", "hex", "data", "9090", "length", 2), unprojected.get("bytes"));
  }

  @Test
  void functionGetAndListValidateDottedProjectionsAndEdgeCases() throws Exception {
    FunctionResource populated =
        new FunctionResource(
            "ram:00100000",
            "main",
            "Global",
            new FunctionResource.Body("ram:00100000", "ram:00100010", 17),
            "int main(int argc)",
            DataTypeReference.named("/int"),
            VariableStorageReference.register("EAX"),
            1,
            "__stdcall",
            List.of(
                new FunctionResource.ParameterResource(
                    0,
                    "argc",
                    DataTypeReference.named("/int"),
                    VariableStorageReference.register("EDI"))),
            List.of(
                new FunctionResource.LocalVariableResource(
                    "local_8",
                    DataTypeReference.named("/int"),
                    VariableStorageReference.serialization("Stack[-0x8]:4"))),
            null,
            false,
            false,
            false,
            false,
            0,
            false,
            false,
            null,
            List.of(),
            null);
    FunctionResource externalEmptyVars =
        new FunctionResource(
            "EXTERNAL:00000001",
            "puts",
            "Global",
            null,
            "int puts(void)",
            DataTypeReference.named("/int"),
            VariableStorageReference.register("EAX"),
            0,
            "default",
            List.of(),
            List.of(),
            null,
            false,
            false,
            false,
            false,
            null,
            true,
            false,
            null,
            List.of(),
            null);

    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if ("getFunction".equals(method)) {
                return "EXTERNAL:00000001".equals(args[0]) ? externalEmptyVars : populated;
              }
              assertEquals("listFunctions", method);
              return Page.scanned(
                  List.of(populated, externalEmptyVars),
                  100,
                  null,
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00100000",
                      "ram:00100010",
                      "ram:00100000",
                      "ram:00100010",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      1L));
            });
    ApiRegistry registry = registryWith(unused(MemoryService.class), functions,
        unused(DataTypeService.class), unused(SymbolService.class), unused(ReferenceService.class));

    @SuppressWarnings("unchecked")
    Map<String, Object> projectedBody =
        (Map<String, Object>)
            registry.dispatch(
                "function.get",
                Map.of(
                    "selector", Map.of("entry", "ram:00100000"),
                    "projection",
                        Map.of(
                            "fields",
                            List.of(
                                "body.start", "parameters.name", "local_variables.storage"))));
    assertEquals(
        Map.of(
            "entry", "ram:00100000",
            "body", Map.of("start", "ram:00100000"),
            "parameters", List.of(Map.of("name", "argc")),
            "local_variables",
                List.of(Map.of("storage", Map.of("kind", "serialization",
                    "serialization", "Stack[-0x8]:4")))),
        projectedBody);

    @SuppressWarnings("unchecked")
    Map<String, Object> projectedExternal =
        (Map<String, Object>)
            registry.dispatch(
                "function.get",
                Map.of(
                    "selector", Map.of("entry", "EXTERNAL:00000001"),
                    "projection",
                        Map.of(
                            "fields",
                            List.of("body.start", "parameters.name", "local_variables.name"))));
    assertEquals(
        Map.of(
            "entry", "EXTERNAL:00000001",
            "parameters", List.of(),
            "local_variables", List.of()),
        projectedExternal);

    @SuppressWarnings("unchecked")
    Map<String, Object> projectedList =
        (Map<String, Object>)
            registry.dispatch(
                "function.list",
                Map.of("projection", Map.of("fields", List.of("body.num_addresses",
                    "parameters.ordinal"))));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) projectedList.get("items");
    assertEquals(2, items.size());
    assertEquals(
        Map.of(
            "entry", "ram:00100000",
            "body", Map.of("num_addresses", 17L),
            "parameters", List.of(Map.of("ordinal", 0))),
        items.get(0));
    assertEquals(
        Map.of("entry", "EXTERNAL:00000001", "parameters", List.of()),
        items.get(1));
  }

  @Test
  void dataTypeGetAndListValidateDottedSignatureProjections() throws Exception {
    DataTypeResource fnType =
        new DataTypeResource(
            "/callback_t",
            "callback_t",
            "/",
            DataTypeResource.Kind.FUNCTION,
            null,
            "",
            null,
            null,
            null,
            new FunctionSignature(
                DataTypeReference.named("/int"),
                List.of(new FunctionSignature.Parameter("ctx", DataTypeReference.untypedPointer())),
                "default",
                false,
                false),
            null);
    DataTypeResource structType =
        new DataTypeResource(
            "/header_t",
            "header_t",
            "/",
            DataTypeResource.Kind.STRUCT,
            4,
            "",
            4,
            List.of(),
            null,
            null,
            null);

    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              if ("getDataType".equals(method)) {
                return "/header_t".equals(args[0]) ? structType : fnType;
              }
              assertEquals("searchDataTypes", method);
              return Page.of(List.of(fnType, structType), 100, null);
            });
    ApiRegistry registry = registryWith(unused(MemoryService.class), unused(FunctionService.class),
        dataTypes, unused(SymbolService.class), unused(ReferenceService.class));

    @SuppressWarnings("unchecked")
    Map<String, Object> projectedFn =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.get",
                Map.of(
                    "selector", Map.of("path", "/callback_t"),
                    "projection", Map.of("fields", List.of("signature.return_type"))));
    assertEquals(
        Map.of(
            "path", "/callback_t",
            "signature", Map.of("return_type", Map.of("kind", "named", "name", "/int"))),
        projectedFn);

    @SuppressWarnings("unchecked")
    Map<String, Object> projectedStruct =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.get",
                Map.of(
                    "selector", Map.of("path", "/header_t"),
                    "projection", Map.of("fields", List.of("signature.parameters"))));
    assertEquals(Map.of("path", "/header_t"), projectedStruct);

    @SuppressWarnings("unchecked")
    Map<String, Object> projectedList =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.list",
                Map.of("projection", Map.of("fields", List.of("signature.parameters"))));
    assertEquals(
        List.of(
            Map.of(
                "path", "/callback_t",
                "signature",
                    Map.of(
                        "parameters",
                        List.of(
                            Map.of(
                                "name", "ctx",
                                "data_type", Map.of("kind", "untyped_pointer"))))),
            Map.of("path", "/header_t")),
        projectedList.get("items"));
  }

  @Test
  void nonProjectedWriteSchemasNonDottedBytesAndInputSignaturesStayStrict() {
    ApiRegistry registry = registryWith(unused(MemoryService.class), unused(FunctionService.class),
        unused(DataTypeService.class), unused(SymbolService.class), unused(ReferenceService.class));

    for (String method : List.of("instruction.get", "instruction.list", "flow_override.list",
        "flow_override.patch", "code_unit.list", "data_unit.list")) {
      Map<?, ?> itemSchema = itemOrResourceSchema(registry.method(method).responseCodec().schema());
      Map<?, ?> bytesSchema = (Map<?, ?>) ((Map<?, ?>) itemSchema.get("properties")).get("bytes");
      assertEquals(List.of("encoding", "data", "length"), bytesSchema.get("required"), method);
    }

    for (String method : List.of("function.create", "function.patch")) {
      Map<?, ?> props =
          (Map<?, ?>) registry.method(method).responseCodec().schema().get("properties");
      Map<?, ?> body = (Map<?, ?>) props.get("body");
      assertEquals(List.of("start", "end", "num_addresses"), body.get("required"), method);
      Map<?, ?> paramItem = (Map<?, ?>) ((Map<?, ?>) props.get("parameters")).get("items");
      assertEquals(
          List.of("ordinal", "name", "data_type", "storage"), paramItem.get("required"), method);
      Map<?, ?> localItem = (Map<?, ?>) ((Map<?, ?>) props.get("local_variables")).get("items");
      assertEquals(List.of("name", "data_type", "storage"), localItem.get("required"), method);
    }

    for (String method : List.of("data_type.create", "data_type.patch", "data_type.upsert")) {
      Map<?, ?> props =
          (Map<?, ?>) registry.method(method).responseCodec().schema().get("properties");
      List<?> signatureOneOf = (List<?>) ((Map<?, ?>) props.get("signature")).get("oneOf");
      Map<?, ?> signatureObject = (Map<?, ?>) signatureOneOf.get(1);
      assertEquals(
          List.of(
              "return_type", "parameters", "calling_convention", "has_var_args", "has_no_return"),
          signatureObject.get("required"),
          method);
    }

    assertEquals(
        List.of("return_type", "parameters", "calling_convention", "has_var_args", "has_no_return"),
        ApiSchemaCatalog.functionSignatureSchema().get("required"));
  }

  @Test
  void apiMethodValidatesProjectedOutputAgainstResponseSchema() {
    Map<String, Object> inputSchema =
        ApiSchemaCatalog.input(ApiSchemaCatalog.props("fields", ApiRegistry.fieldsSchema()));
    Map<String, Object> outputSchema =
        WireSchema.object(
            ApiSchemaCatalog.props("id", WireSchema.string(), "name", WireSchema.string()),
            "id",
            "name");
    ApiMethod<Map<String, Object>, Object> method =
        new ApiMethod<>(
            "test.get",
            "Test method.",
            ApiMethod.MethodEffects.readOnlyMethod(),
            new StrictObjectCodec(StrictObjectCodec.canonicalSchema(inputSchema), inputSchema),
            new JsonValueCodec(outputSchema),
            Set.of("id", "name"),
            List.of("id"),
            request -> Map.of("id", "1", "name", "alpha"));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                method.invokeDecoded(
                    method.decodeRequest(Map.of("projection", Map.of("fields", List.of("id"))))));
    assertEquals(500, error.status());
    assertEquals("invalid_response", error.error().code());
    assertEquals("handler returned a value that violates its output schema", error.getMessage());
    assertEquals("/result/name", error.error().target());
  }

  @Test
  void symbolListAndReferenceListPreserveAdapterCursorOrder() throws Exception {
    SymbolService symbols =
        proxy(
            SymbolService.class,
            (method, args) -> {
              assertEquals("listSymbols", method);
              return Page.scanned(
                  List.of(
                      new SymbolResource(
                          "2", "sym_two", "ram:00100000", "Global", "Label", "USER_DEFINED", true,
                          null),
                      new SymbolResource(
                          "10", "sym_ten", "ram:00100000", "Global", "Label", "USER_DEFINED", false,
                          null)),
                  100,
                  null,
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00100000",
                      "ram:00100000",
                      "ram:00100000",
                      "ram:00100000",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      1L));
            });
    ReferenceService references =
        proxy(
            ReferenceService.class,
            (method, args) -> {
              assertEquals("listReferences", method);
              return Page.of(
                  List.of(
                      new ReferenceResource(
                          "ram:00100000", "ram:00100020", "DATA", 10, false, "DEFAULT"),
                      new ReferenceResource(
                          "ram:00100000", "ram:00100020", "DATA", 2, true, "DEFAULT")),
                  100,
                  null);
            });
    ApiRegistry registry = registryWith(unused(MemoryService.class), unused(FunctionService.class),
        unused(DataTypeService.class), symbols, references);

    @SuppressWarnings("unchecked")
    Map<String, Object> symbolPage =
        (Map<String, Object>) registry.dispatch("symbol.list", Map.of());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> symbolItems = (List<Map<String, Object>>) symbolPage.get("items");
    assertEquals(
        List.of("2", "10"),
        symbolItems.stream().map(row -> String.valueOf(row.get("id"))).toList());

    @SuppressWarnings("unchecked")
    Map<String, Object> referencePage =
        (Map<String, Object>)
            registry.dispatch("reference.list", Map.of("filter", Map.of("direction", "from")));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> referenceItems =
        (List<Map<String, Object>>) referencePage.get("items");
    assertEquals(
        List.of(10, 2),
        referenceItems.stream().map(row -> (Integer) row.get("operand_index")).toList());
  }

  @Test
  void flowOverrideListRequiresSelectorAndDispatchesScopedFilter() throws Exception {
    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              assertEquals("getFlowOverrides", method);
              assertEquals(new FlowOverrideScope.AddressScope("ram:00100000"), args[0]);
              assertEquals(
                  new AddressScanOptions(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS),
                  args[2]);
              InstructionResource item =
                  new InstructionResource(
                      "ram:00100000",
                      5,
                      new ByteSequence(ByteSequence.Encoding.HEX, "e800000000", 5),
                      "CALL",
                      List.of("0x00100005"),
                      FlowOverrideValue.CALL_RETURN,
                      "UNCONDITIONAL_CALL",
                      "CALL_TERMINATOR",
                      null);
              return Page.scanned(
                  List.of(item),
                  100,
                  null,
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00100000",
                      "ram:00100000",
                      "ram:00100000",
                      "ram:00100000",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      1L));
            });
    ApiRegistry registry =
        registryWith(
            unused(MemoryService.class),
            unused(FunctionService.class),
            unused(DataTypeService.class),
            unused(SymbolService.class),
            unused(ReferenceService.class),
            listing);

    for (Map<String, Object> invalidFilter :
        List.<Map<String, Object>>of(
            Map.of(), Map.of("flow_overrides", List.of("call_return")))) {
      ApiException direct =
          assertThrows(
              ApiException.class,
              () -> registry.dispatch("flow_override.list", Map.of("filter", invalidFilter)));
      assertEquals(400, direct.status());
      assertEquals("missing_field", direct.error().code());
      assertEquals("/filter/selector", direct.error().target());

      ApiException batch =
          assertThrows(
              ApiException.class,
              () ->
                  registry.dispatch(
                      "batch.execute",
                      Map.of(
                          "items",
                          List.of(
                              Map.of(
                                  "id", "item-1",
                                  "method", "flow_override.list",
                                  "arguments", Map.of("filter", invalidFilter))))));
      assertEquals(400, batch.status());
      assertEquals("validation_failed", batch.error().code());
      assertEquals("/items", batch.error().target());
      @SuppressWarnings("unchecked")
      List<Map<String, Object>> violations =
          (List<Map<String, Object>>) batch.error().details().get("violations");
      assertEquals(1, violations.size());
      assertEquals("/items/0/arguments/filter/selector", violations.getFirst().get("target"));
      assertEquals("missing_field", violations.getFirst().get("code"));
    }

    @SuppressWarnings("unchecked")
    Map<String, Object> validResult =
        (Map<String, Object>)
            registry.dispatch(
                "flow_override.list",
                Map.of(
                    "filter",
                    Map.of("selector", Map.of("kind", "address", "address", "ram:00100000"))));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) validResult.get("items");
    assertEquals(1, items.size());
    assertEquals("ram:00100000", items.getFirst().get("address"));
    assertEquals("call_return", items.getFirst().get("flow_override"));

    ApiException missingKind =
        assertThrows(ApiException.class, () -> ApiRegistry.flowScope(Map.of()));
    assertEquals(400, missingKind.status());
    assertEquals("missing_field", missingKind.error().code());
    assertEquals("/selector/kind", missingKind.error().target());

    ApiException nullSelector =
        assertThrows(ApiException.class, () -> ApiRegistry.flowScope(null));
    assertEquals(400, nullSelector.status());
    assertEquals("missing_field", nullSelector.error().code());
    assertEquals("/selector/kind", nullSelector.error().target());
  }

  private static Map<?, ?> itemOrResourceSchema(Map<String, Object> schema) {
    Map<?, ?> props = (Map<?, ?>) schema.get("properties");
    if (props.containsKey("items")) {
      return (Map<?, ?>) ((Map<?, ?>) props.get("items")).get("items");
    }
    return schema;
  }

  private static ApiRegistry registryWith(
      MemoryService memory,
      FunctionService functions,
      DataTypeService dataTypes,
      SymbolService symbols,
      ReferenceService references) {
    return registryWith(
        memory, functions, dataTypes, symbols, references, unused(ListingService.class));
  }

  private static ApiRegistry registryWith(
      MemoryService memory,
      FunctionService functions,
      DataTypeService dataTypes,
      SymbolService symbols,
      ReferenceService references,
      ListingService listing) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null));
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            references,
            memory,
            listing,
            functions,
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            symbols,
            dataTypes,
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("toString".equals(method)) return "unused " + type.getSimpleName();
          assertTrue(false, "unexpected call to " + type.getSimpleName() + "." + method);
          return null;
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
