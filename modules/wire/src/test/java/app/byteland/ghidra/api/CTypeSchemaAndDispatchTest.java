package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeAlreadyExistsException;
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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CTypeSchemaAndDispatchTest {

  @Test
  void dataTypeReferenceSchemaAcceptsStringsAndStructuredObjects() {
    Map<String, Object> schema =
        WireSchema.withDefinitions(
            WireSchema.object(Map.of("data_type", WireSchema.dataTypeReference()), "data_type"));

    for (String expr :
        List.of(
            "int",
            "/pkg/Type *",
            "unsigned int",
            "const char *",
            "struct Foo *",
            "int[4]",
            "void *",
            "pointer",
            "void (*)(int)")) {
      WireSchema.validate(Map.of("data_type", expr), schema, "");
      assertEquals(DataTypeReference.expression(expr), ApiRegistry.dataType(expr, "/data_type"));
    }

    WireSchema.validate(
        Map.of("data_type", Map.of("kind", "named", "name", "/int")), schema, "");
    WireSchema.validate(
        Map.of("data_type", Map.of("kind", "untyped_pointer")), schema, "");
    WireSchema.validate(
        Map.of("data_type", Map.of("kind", "pointer", "target", "const char")), schema, "");

    assertThrows(
        ApiException.class, () -> WireSchema.validate(Map.of("data_type", ""), schema, ""));
    assertThrows(ApiException.class, () -> ApiRegistry.dataType("   ", "/data_type"));
  }

  @Test
  void functionPatchDispatchesParametersSignatureAndRejectsConflicts() throws Exception {
    AtomicReference<List<Object>> patchArgs = new AtomicReference<>();
    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if ("patchFunction".equals(method)) {
                patchArgs.set(Arrays.asList(args));
                return null;
              }
              if ("getFunction".equals(method)) {
                return new FunctionResource(
                    "ram:00100000",
                    "target_fn",
                    null,
                    null,
                    "int target_fn(const char * buf)",
                    DataTypeReference.named("/int"),
                    null,
                    1,
                    "__stdcall",
                    List.of(
                        new FunctionResource.ParameterResource(
                            0,
                            "buf",
                            DataTypeReference.pointerTo(DataTypeReference.named("/char")),
                            new VariableStorageReference.Register("RDI"))),
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
                    null,
                    null);
              }
              throw new AssertionError(method);
            });
    ApiRegistry registry = testRegistry(functions, unused(DataTypeService.class));

    registry.dispatch(
        "function.patch",
        Map.of(
            "selector", Map.of("entry", "0x100000"),
            "patch",
                Map.of(
                    "return_type", "unsigned int",
                    "parameters",
                        List.of(
                            Map.of(
                                "ordinal", 0,
                                "name", "buf",
                                "data_type", "const char *",
                                "storage", Map.of("kind", "register", "register", "RDI")),
                            Map.of("name", "cb", "data_type", "void (*)(int)")))));

    List<Object> captured = patchArgs.get();
    assertEquals("0x100000", captured.get(0));
    assertEquals(DataTypeReference.expression("unsigned int"), captured.get(4));
    @SuppressWarnings("unchecked")
    List<FunctionService.ParameterPatch> params =
        (List<FunctionService.ParameterPatch>) captured.get(8);
    assertEquals(2, params.size());
    assertEquals("buf", params.get(0).name());
    assertEquals(DataTypeReference.expression("const char *"), params.get(0).dataType());
    assertEquals(new VariableStorageReference.Register("RDI"), params.get(0).storage());
    assertEquals(DataTypeReference.expression("void (*)(int)"), params.get(1).dataType());

    registry.dispatch(
        "function.patch",
        Map.of(
            "selector", Map.of("entry", "0x100000"),
            "patch", Map.of("signature", "int target_fn(const char *buf, int len)")));
    assertEquals("int target_fn(const char *buf, int len)", patchArgs.get().get(9));

    ApiException conflict =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                            Map.of(
                                "signature", "void f(void)",
                                "return_type", "void"))));
    assertEquals(400, conflict.status());

    ApiException badOrdinal =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                            Map.of(
                                "parameters",
                                List.of(Map.of("ordinal", 2, "data_type", "int"))))));
    assertEquals(400, badOrdinal.status());
  }

  @Test
  void dataTypeCreateAndUpsertSupportDeclarationsAndRejectInvalidEnvelopes() throws Exception {
    AtomicReference<List<Object>> dtCall = new AtomicReference<>();
    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              if ("createDataTypeFromDeclaration".equals(method)) {
                dtCall.set(Arrays.asList(method, Arrays.asList(args)));
                String decl = (String) args[1];
                if (decl.contains("Duplicate")) {
                  throw new DataTypeAlreadyExistsException("/declaration", "already exists");
                }
                return "/net/Packet";
              }
              if ("upsertDataTypeFromDeclaration".equals(method)) {
                return "/Packet";
              }
              if ("getDataType".equals(method)) {
                String path = (String) args[0];
                return new DataTypeResource(
                    path,
                    "Packet",
                    path.startsWith("/net/") ? "/net" : "/",
                    DataTypeResource.Kind.STRUCT,
                    8,
                    "",
                    8,
                    List.of(),
                    null,
                    null,
                    null);
              }
              throw new AssertionError(method);
            });
    ApiRegistry registry = testRegistry(unused(FunctionService.class), dataTypes);

    Object created =
        registry.dispatch(
            "data_type.create",
            Map.of("category_path", "/net", "declaration", "struct Packet { int id; };"));
    assertEquals("/net/Packet", ((Map<?, ?>) created).get("path"));
    assertEquals(
        List.of("createDataTypeFromDeclaration", List.of("/net", "struct Packet { int id; };")),
        dtCall.get());

    Object upserted =
        registry.dispatch(
            "data_type.upsert", Map.of("declaration", "struct Packet { long id; };"));
    assertEquals("/Packet", ((Map<?, ?>) upserted).get("path"));

    DataTypeAlreadyExistsException duplicate =
        assertThrows(
            DataTypeAlreadyExistsException.class,
            () ->
                registry.dispatch(
                    "data_type.create", Map.of("declaration", "struct Duplicate { int x; };")));
    assertEquals(409, ApiFailures.normalize(duplicate).status());

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "data_type.create",
                Map.of(
                    "declaration", "struct Packet { int id; };",
                    "resource", Map.of("kind", "struct", "name", "Packet"))));
    assertThrows(
        ApiException.class,
        () -> registry.dispatch("data_type.create", Map.of("category_path", "/net")));
    assertEquals(56, registry.methodCatalog().methods().size());
  }

  private static ApiRegistry testRegistry(FunctionService functions, DataTypeService dataTypes) {
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
    TransactionRunner tx =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
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
            tx,
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
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
