package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CDeclarationsAndPrototypesWireTest {

  @Test
  void dataTypeReferenceSchemaAcceptsCStringAndStructuredVariants() {
    Map<?, ?> defs =
        (Map<?, ?>)
            ApiRegistry.catalog().methods().stream()
                .filter(method -> method.name().equals("function.patch"))
                .findFirst()
                .orElseThrow()
                .inputSchema()
                .get("$defs");
    Map<?, ?> dataTypeRef = (Map<?, ?>) defs.get("data_type_reference");
    List<?> oneOf = (List<?>) dataTypeRef.get("oneOf");
    assertEquals(5, oneOf.size());
    assertTrue(oneOf.contains(WireSchema.nonBlankString()));
  }

  @Test
  void cTypeStringsDecodeForWritesAndSerializeAsStructuredObjectsOnReads() throws Exception {
    AtomicReference<String> invokedWriteMethod = new AtomicReference<>();
    AtomicReference<List<Object>> writeArguments = new AtomicReference<>();
    AtomicInteger transactions = new AtomicInteger();

    FunctionResource sampleFunction =
        new FunctionResource(
            "ram:00100000",
            "recv_packet",
            null,
            null,
            "int recv_packet(Socket * sock, uint8_t * buf, ulong len)",
            DataTypeReference.named("/int"),
            null,
            3,
            "__stdcall",
            List.of(
                new FunctionResource.ParameterResource(
                    0,
                    "sock",
                    DataTypeReference.pointerTo(DataTypeReference.named("/net/Socket")),
                    VariableStorageReference.register("RDI"))),
            List.of(),
            null,
            false,
            false,
            false,
            false,
            null,
            false,
            false,
            null,
            List.of(),
            null);

    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if (method.equals("getFunction")) {
                return sampleFunction;
              }
              invokedWriteMethod.set(method);
              writeArguments.set(args == null ? List.of() : Arrays.asList(args));
              return null;
            });

    GlobalVariableService globals =
        proxy(
            GlobalVariableService.class,
            (method, args) -> {
              if (method.equals("getGlobalVariable")) {
                return new GlobalVariableResource(
                    "ram:00200000",
                    "table",
                    null,
                    DataTypeReference.arrayOf(DataTypeReference.named("/uint"), 4),
                    16,
                    null,
                    null,
                    "USER_DEFINED");
              }
              invokedWriteMethod.set(method);
              writeArguments.set(args == null ? List.of() : Arrays.asList(args));
              return null;
            });

    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              invokedWriteMethod.set(method);
              writeArguments.set(args == null ? List.of() : Arrays.asList(args));
              return List.of(
                  new DataTypeResource(
                      "/net/Socket",
                      "Socket",
                      "/net",
                      DataTypeResource.Kind.STRUCT,
                      8,
                      null,
                      8,
                      List.of(
                          new DataTypeResource.Field(
                              0,
                              "fd",
                              0,
                              3,
                              DataTypeResource.Kind.BUILTIN,
                              4,
                              null,
                              false,
                              DataTypeReference.named("/int")),
                          new DataTypeResource.Field(
                              1,
                              "next",
                              4,
                              7,
                              DataTypeResource.Kind.POINTER,
                              4,
                              null,
                              false,
                              DataTypeReference.pointerTo(
                                  DataTypeReference.named("/net/Socket")))),
                      null,
                      null,
                      null));
            });

    AtomicBoolean analysisRunning = new AtomicBoolean(false);
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    analysisRunning.get()
                        ? AnalysisResource.Status.RUNNING
                        : AnalysisResource.Status.IDLE,
                    analysisRunning.get(),
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
            globals,
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            dataTypes,
            transaction,
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});
    assertEquals(57, registry.methods().size());
    assertTrue(registry.method("data_type.parse_c").effects().requiresTransaction());
    assertTrue(registry.method("data_type.parse_c").effects().destructive());
    assertFalse(registry.method("data_type.parse_c").effects().idempotent());

    // 1. data_type.parse_c defaults and structured read output
    Map<?, ?> parseResult =
        (Map<?, ?>)
            registry.dispatch(
                "data_type.parse_c",
                Map.of("declarations", "struct Socket { int fd; struct Socket *next; };"));
    assertEquals("parseCDeclarations", invokedWriteMethod.get());
    assertEquals(
        List.of(
            "struct Socket { int fd; struct Socket *next; };",
            "/",
            DataTypeService.ConflictMode.REPLACE),
        writeArguments.get());
    assertEquals(1, transactions.get());
    List<?> parsedItems = (List<?>) parseResult.get("items");
    assertEquals(1, parsedItems.size());
    Map<?, ?> socketItem = (Map<?, ?>) parsedItems.get(0);
    List<?> socketFields = (List<?>) socketItem.get("fields");
    Map<?, ?> nextField = (Map<?, ?>) socketFields.get(1);
    Map<?, ?> nextFieldType = (Map<?, ?>) nextField.get("data_type");
    assertEquals("pointer", nextFieldType.get("kind"));

    // 2. data_type.parse_c explicit category_path and conflict_mode
    registry.dispatch(
        "data_type.parse_c",
        Map.of(
            "declarations", "typedef int sock_t;",
            "category_path", "/net",
            "conflict_mode", "rename"));
    assertEquals(
        List.of("typedef int sock_t;", "/net", DataTypeService.ConflictMode.RENAME),
        writeArguments.get());
    assertEquals(2, transactions.get());

    // 3. data_type.parse_c validation failures
    ApiException blankDecl =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("data_type.parse_c", Map.of("declarations", "   ")));
    assertEquals(400, blankDecl.status());
    assertEquals("/declarations", blankDecl.error().target());

    ApiException oversizedDecl =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.parse_c",
                    Map.of(
                        "declarations",
                        "a".repeat(DataTypeService.MAX_DECLARATIONS_BYTES + 1))));
    assertEquals(400, oversizedDecl.status());
    assertEquals("invalid_value", oversizedDecl.error().code());
    assertEquals("/declarations", oversizedDecl.error().target());

    String multibyteDecl = "/* " + "\u00e9".repeat(33_000) + " */ typedef int x;";
    assertTrue(multibyteDecl.length() <= DataTypeService.MAX_DECLARATIONS_BYTES);
    assertTrue(
        multibyteDecl.getBytes(StandardCharsets.UTF_8).length
            > DataTypeService.MAX_DECLARATIONS_BYTES);
    ApiException multibyteDeclErr =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("data_type.parse_c", Map.of("declarations", multibyteDecl)));
    assertEquals(400, multibyteDeclErr.status());
    assertEquals("invalid_value", multibyteDeclErr.error().code());
    assertEquals("/declarations", multibyteDeclErr.error().target());

    ApiException badConflict =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.parse_c",
                    Map.of("declarations", "typedef int x;", "conflict_mode", "overwrite")));
    assertEquals(400, badConflict.status());
    assertEquals("/conflict_mode", badConflict.error().target());

    // 4. Reject mutations while auto-analysis runs and do not open a transaction
    int txBeforeBusy = transactions.get();
    analysisRunning.set(true);
    ApiException busy =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("data_type.parse_c", Map.of("declarations", "typedef int x;")));
    assertEquals(409, busy.status());
    assertEquals("analysis_in_progress", busy.error().code());
    assertEquals(txBeforeBusy, transactions.get());
    analysisRunning.set(false);

    // 5. C type strings on parameter and global variable writes
    Map<?, ?> patchedParam =
        (Map<?, ?>)
            registry.dispatch(
                "function_parameter.patch",
                Map.of(
                    "selector", Map.of("entry", "0x100000", "ordinal", 0),
                    "patch", Map.of("data_type", "int (*)(void *)")));
    assertEquals("patchParameter", invokedWriteMethod.get());
    assertEquals(DataTypeReference.cExpression("int (*)(void *)"), writeArguments.get().get(3));
    assertEquals("pointer", ((Map<?, ?>) patchedParam.get("data_type")).get("kind"));

    Map<?, ?> upsertedGlobal =
        (Map<?, ?>)
            registry.dispatch(
                "global_variable.upsert",
                Map.of(
                    "resource",
                    Map.of(
                        "address", "0x200000",
                        "name", "table",
                        "data_type", "const uint32_t[4]")));
    assertEquals("writeGlobalVariable", invokedWriteMethod.get());
    assertEquals("array", ((Map<?, ?>) upsertedGlobal.get("data_type")).get("kind"));

    ApiException blankTypeRef =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function_parameter.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000", "ordinal", 0),
                        "patch", Map.of("data_type", "  "))));
    assertEquals(400, blankTypeRef.status());
    assertEquals("/patch/data_type", blankTypeRef.error().target());

    // 6. function.patch signature support and conflict checks
    Map<?, ?> patchedFn =
        (Map<?, ?>)
            registry.dispatch(
                "function.patch",
                Map.of(
                    "selector", Map.of("entry", "0x100000"),
                    "patch",
                    Map.of(
                        "signature",
                        "int recv_packet(Socket *sock, const uint8_t *buf, size_t len)")));
    assertEquals("patchFunction", invokedWriteMethod.get());
    assertEquals(
        "int recv_packet(Socket *sock, const uint8_t *buf, size_t len)",
        writeArguments.get().get(4));
    assertEquals("named", ((Map<?, ?>) patchedFn.get("return_type")).get("kind"));

    ApiException returnTypeConflict =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                        Map.of(
                            "signature", "int recv_packet(void)",
                            "return_type", "int"))));
    assertEquals(400, returnTypeConflict.status());
    assertEquals("conflicting_fields", returnTypeConflict.error().code());
    assertEquals("/patch/signature", returnTypeConflict.error().target());

    ApiException ccConflict =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                        Map.of(
                            "signature", "int recv_packet(void)",
                            "calling_convention", "__cdecl"))));
    assertEquals(400, ccConflict.status());
    assertEquals("conflicting_fields", ccConflict.error().code());
    assertEquals("/patch/signature", ccConflict.error().target());

    ApiException paramsConflict =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                        Map.of(
                            "signature", "int recv_packet(void)",
                            "parameters", List.of()))));
    assertEquals(400, paramsConflict.status());
    assertEquals("conflicting_fields", paramsConflict.error().code());
    assertEquals("/patch/signature", paramsConflict.error().target());

    // 7. function.patch atomic parameters support (C type strings, storage, and empty list)
    registry.dispatch(
        "function.patch",
        Map.of(
            "selector", Map.of("entry", "0x100000"),
            "patch",
            Map.of(
                "return_type", "int",
                "parameters",
                List.of(
                    Map.of(
                        "name", "sock",
                        "data_type", "Socket *",
                        "storage", Map.of("kind", "register", "register", "R12")),
                    Map.of("data_type", Map.of("kind", "named", "name", "/ulong"))))));
    assertEquals("patchFunction", invokedWriteMethod.get());
    assertEquals(
        List.of(
            new FunctionService.ParameterPatch(
                "sock",
                DataTypeReference.cExpression("Socket *"),
                VariableStorageReference.register("R12")),
            new FunctionService.ParameterPatch(
                null, DataTypeReference.named("/ulong"), null)),
        writeArguments.get().get(8));

    registry.dispatch(
        "function.patch",
        Map.of(
            "selector", Map.of("entry", "0x100000"),
            "patch", Map.of("parameters", List.of())));
    assertEquals(List.of(), writeArguments.get().get(8));

    ApiException blankNestedParamType =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                        Map.of("parameters", List.of(Map.of("name", "bad", "data_type", "   "))))));
    assertEquals(400, blankNestedParamType.status());
    assertEquals("/patch/parameters/0/data_type", blankNestedParamType.error().target());

    // 8. Check UTF-8 byte-size caps on C type strings and C signature strings.
    String exactMaxType =
        " ".repeat(DataTypeReference.MAX_EXPRESSION_BYTES - "int".length()) + "int";
    assertEquals(
        DataTypeReference.MAX_EXPRESSION_BYTES,
        exactMaxType.getBytes(StandardCharsets.UTF_8).length);
    registry.dispatch(
        "function_parameter.patch",
        Map.of(
            "selector", Map.of("entry", "0x100000", "ordinal", 0),
            "patch", Map.of("data_type", exactMaxType)));
    assertEquals(DataTypeReference.cExpression("int"), writeArguments.get().get(3));

    invokedWriteMethod.set(null);
    ApiException oversizedTypeAscii =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function_parameter.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000", "ordinal", 0),
                        "patch",
                        Map.of(
                            "data_type",
                            "a".repeat(DataTypeReference.MAX_EXPRESSION_BYTES + 1)))));
    assertEquals(400, oversizedTypeAscii.status());
    assertEquals("invalid_value", oversizedTypeAscii.error().code());
    assertEquals("/patch/data_type", oversizedTypeAscii.error().target());
    assertEquals(null, invokedWriteMethod.get());

    String multibyteType = "/* " + "\u00e9".repeat(2_050) + " */ int";
    assertTrue(multibyteType.length() <= DataTypeReference.MAX_EXPRESSION_BYTES);
    assertTrue(
        multibyteType.getBytes(StandardCharsets.UTF_8).length
            > DataTypeReference.MAX_EXPRESSION_BYTES);
    ApiException oversizedTypeUtf8 =
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
                            List.of(Map.of("name", "p", "data_type", multibyteType))))));
    assertEquals(400, oversizedTypeUtf8.status());
    assertEquals("invalid_value", oversizedTypeUtf8.error().code());
    assertEquals("/patch/parameters/0/data_type", oversizedTypeUtf8.error().target());

    ApiException oversizedNestedPointerTarget =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "global_variable.patch",
                    Map.of(
                        "selector", Map.of("address", "0x200000"),
                        "patch",
                        Map.of(
                            "data_type",
                            Map.of(
                                "kind",
                                "pointer",
                                "target",
                                " ".repeat(DataTypeReference.MAX_EXPRESSION_BYTES) + "int")))));
    assertEquals(400, oversizedNestedPointerTarget.status());
    assertEquals("invalid_value", oversizedNestedPointerTarget.error().code());
    assertEquals("/patch/data_type/target", oversizedNestedPointerTarget.error().target());

    String exactMaxSignature =
        "int f("
            + " ".repeat(FunctionService.MAX_SIGNATURE_BYTES - "int f(int x)".length())
            + "int x)";
    assertEquals(
        FunctionService.MAX_SIGNATURE_BYTES,
        exactMaxSignature.getBytes(StandardCharsets.UTF_8).length);
    registry.dispatch(
        "function.patch",
        Map.of(
            "selector", Map.of("entry", "0x100000"),
            "patch", Map.of("signature", exactMaxSignature)));
    assertEquals(exactMaxSignature, writeArguments.get().get(4));

    invokedWriteMethod.set(null);
    ApiException oversizedSigAscii =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch",
                        Map.of(
                            "signature",
                            "a".repeat(FunctionService.MAX_SIGNATURE_BYTES + 1)))));
    assertEquals(400, oversizedSigAscii.status());
    assertEquals("invalid_value", oversizedSigAscii.error().code());
    assertEquals("/patch/signature", oversizedSigAscii.error().target());
    assertEquals(null, invokedWriteMethod.get());

    String multibyteSig = "/* " + "\u00e9".repeat(4_100) + " */ int f(void)";
    assertTrue(multibyteSig.length() <= FunctionService.MAX_SIGNATURE_BYTES);
    assertTrue(
        multibyteSig.getBytes(StandardCharsets.UTF_8).length > FunctionService.MAX_SIGNATURE_BYTES);
    ApiException oversizedSigUtf8 =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x100000"),
                        "patch", Map.of("signature", multibyteSig))));
    assertEquals(400, oversizedSigUtf8.status());
    assertEquals("invalid_value", oversizedSigUtf8.error().code());
    assertEquals("/patch/signature", oversizedSigUtf8.error().target());
    assertEquals(null, invokedWriteMethod.get());
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
