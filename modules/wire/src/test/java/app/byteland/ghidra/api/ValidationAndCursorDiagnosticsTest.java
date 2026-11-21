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
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ValidationAndCursorDiagnosticsTest {
  private ApiRegistry registry;

  @BeforeEach
  void setUp() {
    ListingService listingService =
        proxy(
            ListingService.class,
            (method, args) -> {
              if ("listCodeUnits".equals(method)) {
                String cursor = (String) args[4];
                if (cursor == null) {
                  return Page.scanned(
                      List.of(
                          new CodeUnitResource(
                              "0x1000",
                              CodeUnitResource.Kind.INSTRUCTION,
                              1,
                              new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                              "NOP",
                              "NOP",
                              List.of(),
                              null,
                              null,
                              null)),
                      1,
                      "0x1001",
                      new ScanProgress(
                          ScanProgress.Kind.ADDRESS,
                          null,
                          null,
                          "0x1000",
                          "0x1000",
                          false,
                          ScanProgress.StopReason.LIMIT,
                          1));
                }
                assertEquals("0x1001", cursor);
                return Page.scanned(
                    List.of(
                        new CodeUnitResource(
                            "0x1001",
                            CodeUnitResource.Kind.INSTRUCTION,
                            1,
                            new ByteSequence(ByteSequence.Encoding.HEX, "c3", 1),
                            "RET",
                            "RET",
                            List.of(),
                            null,
                            null,
                            null)),
                    1,
                    null,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        null,
                        null,
                        "0x1001",
                        "0x1001",
                        true,
                        ScanProgress.StopReason.COMPLETED,
                        1));
              }
              throw new AssertionError("Unexpected ListingService method: " + method);
            });

    DataTypeService dataTypeService =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              if ("listCategories".equals(method)) {
                String path = (String) args[0];
                assertEquals("/", path);
                String cursor = (String) args[2];
                if (cursor == null) {
                  return Page.of(
                      List.of(new DataTypeCategoryResource("/catA", "catA", 0, 1)), 1, "/catA");
                }
                assertEquals("/catA", cursor);
                return Page.of(
                    List.of(new DataTypeCategoryResource("/catB", "catB", 0, 2)), 1, null);
              }
              if ("searchDataTypes".equals(method)) {
                String query = (String) args[0];
                assertEquals("", query);
                String cursor = (String) args[4];
                if (cursor == null) {
                  return Page.of(
                      List.of(
                          new DataTypeResource(
                              "/int",
                              "int",
                              "/",
                              DataTypeResource.Kind.OTHER,
                              4,
                              null,
                              4,
                              null,
                              null,
                              null,
                              null)),
                      1,
                      "/int");
                }
                assertEquals("/int", cursor);
                return Page.of(
                    List.of(
                        new DataTypeResource(
                            "/uint",
                            "uint",
                            "/",
                            DataTypeResource.Kind.OTHER,
                            4,
                            null,
                            4,
                            null,
                            null,
                            null,
                            null)),
                    1,
                    null);
              }
              throw new AssertionError("Unexpected DataTypeService method: " + method);
            });

    FunctionService functionService =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if ("getCallees".equals(method)) {
                String cursor = (String) args[2];
                if (cursor == null) {
                  return Page.of(
                      List.of(
                          new FunctionCallResource(
                              "0x2000",
                              "helper_a",
                              "0x1004",
                              FunctionCallResource.Direction.CALLEES,
                              "Global",
                              null)),
                      1,
                      "0x2000");
                }
                assertEquals("0x2000", cursor);
                return Page.of(
                    List.of(
                        new FunctionCallResource(
                            "0x2010",
                            "helper_b",
                            "0x1008",
                            FunctionCallResource.Direction.CALLEES,
                            "Global",
                            null)),
                    1,
                    null);
              }
              throw new AssertionError("Unexpected FunctionService method: " + method);
            });

    AnalysisService analysisService =
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

    TransactionRunner transactions =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException error) {
              throw error;
            } catch (Exception error) {
              throw new RuntimeException(error);
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
            listingService,
            functionService,
            unused(GlobalVariableService.class),
            analysisService,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            dataTypeService,
            transactions,
            "sample.bin");
    registry = new ApiRegistry(services, "session-alpha", Map::of, () -> {});
  }

  @Test
  void discriminatedUnionsReportExactBranchAndNestedTargetPointers() {
    ApiException missingBaseType =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of("resource", Map.of("kind", "typedef", "name", "MyAlias"))));
    assertEquals(400, missingBaseType.status());
    assertEquals("missing_field", missingBaseType.error().code());
    assertEquals("/resource/base_type", missingBaseType.error().target());

    ApiException nestedPointerMissingTarget =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "typedef",
                            "name",
                            "MyPtr",
                            "base_type",
                            Map.of("kind", "pointer")))));
    assertEquals(400, nestedPointerMissingTarget.status());
    assertEquals("missing_field", nestedPointerMissingTarget.error().code());
    assertEquals("/resource/base_type/target", nestedPointerMissingTarget.error().target());

    ApiException functionParamPointerMissingTarget =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "function",
                            "name",
                            "Callback",
                            "signature",
                            Map.of(
                                "return_type", Map.of("kind", "named", "name", "void"),
                                "parameters", List.of(Map.of("data_type", Map.of("kind", "pointer"))),
                                "calling_convention", "default",
                                "has_var_args", false,
                                "has_no_return", false)))));
    assertEquals(400, functionParamPointerMissingTarget.status());
    assertEquals("missing_field", functionParamPointerMissingTarget.error().code());
    assertEquals(
        "/resource/signature/parameters/0/data_type/target",
        functionParamPointerMissingTarget.error().target());

    ApiException unknownResourceKind =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of("resource", Map.of("kind", "bogus_kind", "name", "Bad"))));
    assertEquals(400, unknownResourceKind.status());
    assertEquals("invalid_enum", unknownResourceKind.error().code());
    assertEquals("/resource/kind", unknownResourceKind.error().target());

    ApiException flowRangeMissingEnd =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "flow_override.patch",
                    Map.of(
                        "selector", Map.of("kind", "range", "start", "0x1000"),
                        "patch", Map.of("flow_override", "return"))));
    assertEquals(400, flowRangeMissingEnd.status());
    assertEquals("missing_field", flowRangeMissingEnd.error().code());
    assertEquals("/selector/end", flowRangeMissingEnd.error().target());

    ApiException storageMissingRegister =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x1000"),
                        "patch", Map.of("return_storage", Map.of("kind", "register")))));
    assertEquals(400, storageMissingRegister.status());
    assertEquals("missing_field", storageMissingRegister.error().code());
    assertEquals("/patch/return_storage/register", storageMissingRegister.error().target());

    ApiException enumPatchExtraField =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector", Map.of("path", "/MyEnum"),
                        "patch",
                            Map.of(
                                "kind",
                                "enum",
                                "add_values",
                                List.of(Map.of("name", "A", "extra", 1))))));
    assertEquals(400, enumPatchExtraField.status());
    assertEquals("unknown_field", enumPatchExtraField.error().code());
    assertEquals("/patch/add_values/0/extra", enumPatchExtraField.error().target());

    Map<String, Object> batchSchema = registry.method("batch.execute").requestCodec().schema();
    ApiException unknownBatchMethod =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of(
                        "items",
                        List.of(
                            Map.of(
                                "id", "step-1",
                                "method", "nonexistent.method",
                                "arguments", Map.of()))),
                    batchSchema,
                    ""));
    assertEquals("invalid_enum", unknownBatchMethod.error().code());
    assertEquals("/items/0/method", unknownBatchMethod.error().target());

    ApiException batchBranchMissingField =
        assertThrows(
            ApiException.class,
            () ->
                WireSchema.validate(
                    Map.of(
                        "items",
                        List.of(
                            Map.of(
                                "id", "step-1",
                                "method", "data_type.create",
                                "arguments",
                                    Map.of(
                                        "resource",
                                        Map.of("kind", "typedef", "name", "MissingBase"))))),
                    batchSchema,
                    ""));
    assertEquals("missing_field", batchBranchMissingField.error().code());
    assertEquals(
        "/items/0/arguments/resource/base_type", batchBranchMissingField.error().target());
  }

  @Test
  void enumPatchValidationEmitsActionSpecificPointers() {
    ApiException removeMissingSelector =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector", Map.of("path", "/MyEnum"),
                        "patch", Map.of("kind", "enum", "remove_values", List.of(Map.of())))));
    assertEquals("/patch/remove_values/0", removeMissingSelector.error().target());

    ApiException renameMissingNewName =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector", Map.of("path", "/MyEnum"),
                        "patch",
                            Map.of(
                                "kind", "enum", "rename_values", List.of(Map.of("name", "OLD"))))));
    assertEquals("/patch/rename_values/0/new_name", renameMissingNewName.error().target());

    ApiException updateMissingName =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector", Map.of("path", "/MyEnum"),
                        "patch",
                            Map.of("kind", "enum", "update_values", List.of(Map.of("value", 2L))))));
    assertEquals("/patch/update_values/0/name", updateMissingName.error().target());
  }

  @Test
  @SuppressWarnings("unchecked")
  void paginatedQueriesAcceptOmittedDefaultsAndEmptyRangesAcrossPages() throws Exception {
    Map<String, Object> codeUnitPage1 =
        (Map<String, Object>)
            registry.dispatch(
                "code_unit.list",
                Map.of(
                    "scan", Map.of("range", Map.of()),
                    "filter", Map.of("kind", "all"),
                    "page", Map.of("limit", 1)));
    String codeUnitCursor = (String) codeUnitPage1.get("next_cursor");
    assertNotNull(codeUnitCursor);
    Map<String, Object> codeUnitPage2 =
        (Map<String, Object>)
            registry.dispatch("code_unit.list", Map.of("page", Map.of("cursor", codeUnitCursor)));
    assertEquals(1, ((List<?>) codeUnitPage2.get("items")).size());

    ApiException changedCodeUnitFilter =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "code_unit.list",
                    Map.of(
                        "filter", Map.of("kind", "instruction"),
                        "page", Map.of("cursor", codeUnitCursor))));
    assertEquals("invalid_cursor", changedCodeUnitFilter.error().code());
    assertEquals("/page/cursor", changedCodeUnitFilter.error().target());

    Map<String, Object> categoryPage1 =
        (Map<String, Object>)
            registry.dispatch(
                "data_type_category.list",
                Map.of("filter", Map.of("path", "/"), "page", Map.of("limit", 1)));
    String categoryCursor = (String) categoryPage1.get("next_cursor");
    assertNotNull(categoryCursor);
    Map<String, Object> categoryPage2 =
        (Map<String, Object>)
            registry.dispatch(
                "data_type_category.list", Map.of("page", Map.of("cursor", categoryCursor)));
    assertEquals(1, ((List<?>) categoryPage2.get("items")).size());

    Map<String, Object> dataTypePage1 =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.list",
                Map.of("filter", Map.of("query", ""), "page", Map.of("limit", 1)));
    String dataTypeCursor = (String) dataTypePage1.get("next_cursor");
    assertNotNull(dataTypeCursor);
    Map<String, Object> dataTypePage2 =
        (Map<String, Object>)
            registry.dispatch("data_type.list", Map.of("page", Map.of("cursor", dataTypeCursor)));
    assertEquals(1, ((List<?>) dataTypePage2.get("items")).size());

    Map<String, Object> callPage1 =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of(
                    "filter", Map.of("entry", "0x1000", "direction", "callees"),
                    "page", Map.of("limit", 1)));
    String callCursor = (String) callPage1.get("next_cursor");
    assertNotNull(callCursor);
    Map<String, Object> callPage2 =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of("filter", Map.of("entry", "0x1000"), "page", Map.of("cursor", callCursor)));
    assertEquals(1, ((List<?>) callPage2.get("items")).size());
  }

  @Test
  void cursorTokensPruneEmptyMapsAndReturnDistinctPlainEnglishErrors() {
    String emptyFingerprint = CursorTokens.queryFingerprint(Map.of());
    assertEquals(
        emptyFingerprint,
        CursorTokens.queryFingerprint(
            Map.of("scan", Map.of("range", Map.of()), "filter", Map.of())));
    assertEquals(
        emptyFingerprint,
        CursorTokens.queryFingerprint(Map.of("range", Map.of(), "filter", Map.of())));

    String validToken = CursorTokens.encode("code_unit", "sess-1", emptyFingerprint, "0x1000");
    assertEquals(
        "0x1000",
        CursorTokens.decode(validToken, "code_unit", "sess-1", emptyFingerprint, "/page/cursor"));

    ApiException badBase64 =
        assertThrows(
            ApiException.class,
            () ->
                CursorTokens.decode(
                    "%%%not_base64%%%", "code_unit", "sess-1", emptyFingerprint, "/page/cursor"));

    String badFormatToken =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("only\ntwo".getBytes(StandardCharsets.UTF_8));
    ApiException badFormat =
        assertThrows(
            ApiException.class,
            () ->
                CursorTokens.decode(
                    badFormatToken, "code_unit", "sess-1", emptyFingerprint, "/page/cursor"));

    String badSigToken =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                ("code_unit\nsess-1\n" + emptyFingerprint + "\n0x1000\ninvalid_sig")
                    .getBytes(StandardCharsets.UTF_8));
    ApiException badSignature =
        assertThrows(
            ApiException.class,
            () ->
                CursorTokens.decode(
                    badSigToken, "code_unit", "sess-1", emptyFingerprint, "/page/cursor"));

    ApiException resourceMismatch =
        assertThrows(
            ApiException.class,
            () ->
                CursorTokens.decode(
                    validToken, "symbol", "sess-1", emptyFingerprint, "/page/cursor"));

    ApiException sessionMismatch =
        assertThrows(
            ApiException.class,
            () ->
                CursorTokens.decode(
                    validToken, "code_unit", "sess-2", emptyFingerprint, "/page/cursor"));

    String changedFingerprint =
        CursorTokens.queryFingerprint(Map.of("filter", Map.of("kind", "data")));
    ApiException filterMismatch =
        assertThrows(
            ApiException.class,
            () ->
                CursorTokens.decode(
                    validToken, "code_unit", "sess-1", changedFingerprint, "/page/cursor"));

    List<ApiException> failures =
        List.of(
            badBase64,
            badFormat,
            badSignature,
            resourceMismatch,
            sessionMismatch,
            filterMismatch);
    Set<String> messages = new HashSet<>();
    for (ApiException failure : failures) {
      assertEquals(400, failure.status());
      assertEquals("invalid_cursor", failure.error().code());
      assertEquals("/page/cursor", failure.error().target());
      assertFalse(failure.getMessage().equals("cursor is invalid"), failure.getMessage());
      messages.add(failure.getMessage());
    }
    assertEquals(failures.size(), messages.size(), "Expected distinct cursor error messages");
  }

  private interface Invocation {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("Unexpected service call: " + method);
        });
  }

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> invocation.invoke(method.getName(), args)));
  }
}
