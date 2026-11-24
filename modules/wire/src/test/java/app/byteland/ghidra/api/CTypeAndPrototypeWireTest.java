package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CTypeAndPrototypeWireTest {
  @Test
  void allTenWriteMethodsReferencingDataTypeReferenceAcceptStringsAndStructuredObjects() {
    ApiCatalog catalog = ApiRegistry.catalog();
    List<String> writeMethodsWithDataTypeRef = new ArrayList<>();
    for (ApiCatalog.MethodDescriptor descriptor : catalog.methods()) {
      @SuppressWarnings("unchecked")
      Map<String, Object> effects = (Map<String, Object>) descriptor.contractValue().get("effects");
      if (Boolean.TRUE.equals(effects.get("mutates_program"))
          && !"batch.execute".equals(descriptor.name())
          && containsDataTypeRef(descriptor.inputSchema().get("properties"))) {
        writeMethodsWithDataTypeRef.add(descriptor.name());
      }
    }
    assertEquals(
        List.of(
            "global_variable.create",
            "global_variable.patch",
            "global_variable.upsert",
            "function.patch",
            "function_parameter.create",
            "function_parameter.patch",
            "function_local_variable.patch",
            "data_type.create",
            "data_type.patch",
            "data_type.upsert"),
        writeMethodsWithDataTypeRef);

    Map<String, Object> schema = WireSchema.withDefinitions(WireSchema.dataTypeReference());
    WireSchema.validate("const char *", schema, "/data_type");
    WireSchema.validate("int (*)[4]", schema, "/data_type");
    WireSchema.validate("void (*)(int)", schema, "/data_type");
    WireSchema.validate(Map.of("kind", "named", "name", "/int"), schema, "/data_type");
    WireSchema.validate(
        Map.of("kind", "pointer", "target", Map.of("kind", "named", "name", "/char")),
        schema,
        "/data_type");
    assertThrows(ApiException.class, () -> WireSchema.validate("", schema, "/data_type"));
    assertThrows(ApiException.class, () -> ApiRegistry.dataType("   ", "/data_type"));
  }

  @Test
  void parseCValidatesInputsAndEmitsCanonicalStructuredReferences() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    AtomicReference<List<Object>> captured = new AtomicReference<>();
    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              assertEquals("parseC", method);
              captured.set(List.of(args[0], args[1]));
              return List.of(
                  new DataTypeResource(
                      "/net/Packet",
                      "Packet",
                      "/net",
                      DataTypeResource.Kind.STRUCT,
                      8,
                      "",
                      8,
                      List.of(
                          new DataTypeResource.Field(
                              0,
                              "buf",
                              0,
                              7,
                              DataTypeResource.Kind.POINTER,
                              8,
                              null,
                              false,
                              DataTypeReference.pointerTo(DataTypeReference.named("/char")))),
                      null,
                      null,
                      null));
            });
    ApiRegistry registry = createRegistry(unused(FunctionService.class), dataTypes, transactions);

    @SuppressWarnings("unchecked")
    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.parse_c",
                Map.of(
                    "source", "struct Packet { const char *buf; };",
                    "category_path", "/net"));
    assertEquals(List.of("struct Packet { const char *buf; };", "/net"), captured.get());
    assertEquals(1, transactions.get());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(1, items.size());
    assertEquals("/net/Packet", items.getFirst().get("path"));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> fields = (List<Map<String, Object>>) items.getFirst().get("fields");
    assertEquals(
        Map.of("kind", "pointer", "target", Map.of("kind", "named", "name", "/char")),
        fields.getFirst().get("data_type"));

    ApiException blankSource =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("data_type.parse_c", Map.of("source", "   ")));
    assertEquals(400, blankSource.status());
  }

  @Test
  void functionPatchEnforcesConflictingFieldsAndForwardsParametersOrSignature() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    AtomicReference<Object[]> patchCall = new AtomicReference<>();
    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if ("patchFunction".equals(method)) {
                patchCall.set(args);
                return null;
              }
              assertEquals("getFunction", method);
              return new FunctionResource(
                  "ram:00401000",
                  "process",
                  null,
                  null,
                  "int process(void)",
                  DataTypeReference.named("/int"),
                  new VariableStorageReference.Register("EAX"),
                  2,
                  "__stdcall",
                  List.of(),
                  List.of(),
                  null,
                  false,
                  false,
                  false,
                  true,
                  null,
                  false,
                  false,
                  null,
                  List.of(),
                  null);
            });
    ApiRegistry registry = createRegistry(functions, unused(DataTypeService.class), transactions);

    for (Map<String, Object> conflictingPatch :
        List.<Map<String, Object>>of(
            Map.of("signature", "int f(int a)", "return_type", "int"),
            Map.of("signature", "int f(int a)", "calling_convention", "__cdecl"),
            Map.of(
                "signature",
                "int f(int a)",
                "parameters",
                List.of(Map.of("name", "a", "data_type", "int"))))) {
      ApiException error =
          assertThrows(
              ApiException.class,
              () ->
                  registry.dispatch(
                      "function.patch",
                      Map.of("selector", Map.of("entry", "0x401000"), "patch", conflictingPatch)));
      assertEquals(400, error.status());
      assertEquals("conflicting_fields", error.error().code());
    }

    registry.dispatch(
        "function.patch",
        Map.of(
            "selector", Map.of("entry", "0x401000"),
            "patch", Map.of("signature", "int process(const char *buf, void (*cb)(int))")));
    Object[] sigArgs = patchCall.get();
    assertNotNull(sigArgs);
    assertEquals("int process(const char *buf, void (*cb)(int))", sigArgs[9]);

    registry.dispatch(
        "function.patch",
        Map.of(
            "selector",
            Map.of("entry", "0x401000"),
            "patch",
            Map.of(
                "return_type",
                "const char *",
                "parameters",
                List.of(
                    Map.of(
                        "name",
                        "second",
                        "data_type",
                        "int (*)[4]",
                        "storage",
                        Map.of("kind", "register", "register", "RSI")),
                    Map.of("name", "first", "data_type", "uint32_t")))));
    Object[] paramArgs = patchCall.get();
    assertEquals(new DataTypeReference.CType("const char *"), paramArgs[4]);
    @SuppressWarnings("unchecked")
    List<FunctionService.ParameterPatch> params =
        (List<FunctionService.ParameterPatch>) paramArgs[8];
    assertEquals(2, params.size());
    assertEquals("second", params.get(0).name());
    assertEquals(new DataTypeReference.CType("int (*)[4]"), params.get(0).dataType());
    assertEquals(new VariableStorageReference.Register("RSI"), params.get(0).storage());
    assertEquals("first", params.get(1).name());
    assertEquals(new DataTypeReference.CType("uint32_t"), params.get(1).dataType());
  }

  private static boolean containsDataTypeRef(Object value) {
    if (value instanceof Map<?, ?> map) {
      if ("#/$defs/data_type_reference".equals(map.get("$ref"))) {
        return true;
      }
      for (Object child : map.values()) {
        if (containsDataTypeRef(child)) {
          return true;
        }
      }
    } else if (value instanceof List<?> list) {
      for (Object item : list) {
        if (containsDataTypeRef(item)) {
          return true;
        }
      }
    }
    return false;
  }

  private static ApiRegistry createRegistry(
      FunctionService functions, DataTypeService dataTypes, AtomicInteger transactions) {
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
                    null));
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            transactions.incrementAndGet();
            try {
              return operation.execute();
            } catch (RuntimeException ex) {
              throw ex;
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
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            functions,
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
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
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.isDefault()) {
                return java.lang.invoke.MethodHandles.privateLookupIn(
                        type, java.lang.invoke.MethodHandles.lookup())
                    .unreflectSpecial(method, type)
                    .bindTo(proxy)
                    .invokeWithArguments(args);
              }
              return handler.invoke(method.getName(), args);
            }));
  }
}
