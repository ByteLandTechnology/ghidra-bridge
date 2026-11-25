package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.ControlFlowGraphResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.listing.ListingWindowResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceContextResource;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CompositeMethodsTest {

  @Test
  void listingWindowGetEncodesCursorAndSupportsBatchExecution() throws Exception {
    AtomicReference<String> observedCursor = new AtomicReference<>();
    ListingWindowResource window =
        new ListingWindowResource(
            List.of(
                new CodeUnitResource(
                    "ram:00401000",
                    CodeUnitResource.Kind.INSTRUCTION,
                    1,
                    new ByteSequence(ByteSequence.Encoding.HEX, "c3", 1),
                    "RET",
                    "RET",
                    List.of(),
                    null)),
            List.of(
                new DataUnitResource(
                    "ram:00401004",
                    4,
                    DataTypeReference.named("/dword"),
                    "7",
                    "7h",
                    new ByteSequence(ByteSequence.Encoding.HEX, "07000000", 4))),
            List.of(
                new SymbolResource(
                    "42", "entry_label", "ram:00401000", "Global", "Label", "USER_DEFINED", true,
                    null)),
            List.of(),
            List.of(
                new CommentResource("ram:00401000", CommentResource.Type.EOL, "return site")),
            List.of(
                new ReferenceResource(
                    "ram:00400ff0", "ram:00401000", "UNCONDITIONAL_CALL", 0, true, "ANALYSIS")),
            List.of(),
            "ram:00401000",
            new ScanProgress(
                ScanProgress.Kind.ADDRESS,
                "ram:00401000",
                null,
                "ram:00401000",
                "ram:00401000",
                false,
                ScanProgress.StopReason.LIMIT,
                4L));

    ApiRegistry registry =
        createRegistry(
            (method, args) -> {
              assertEquals("getListingWindow", method);
              AddressScanOptions scan = (AddressScanOptions) args[0];
              assertEquals("ram:00401000", scan.start());
              assertEquals(15000, scan.timeoutMs());
              assertEquals(80, args[1]);
              assertEquals("all", args[2]);
              observedCursor.set((String) args[3]);
              return window;
            },
            unusedHandler(),
            unusedHandler());

    @SuppressWarnings("unchecked")
    Map<String, Object> first =
        (Map<String, Object>)
            registry.dispatch(
                "listing_window.get",
                Map.of(
                    "filter", Map.of("kind", "all"),
                    "page", Map.of("limit", 80),
                    "scan",
                        Map.of(
                            "range", Map.of("start", "ram:00401000"),
                            "timeout_ms", 15000)));
    assertFalse(observedCursor.get() != null);
    String token = (String) first.get("next_cursor");
    assertNotNull(token);
    assertFalse(token.isBlank());
    assertFalse("ram:00401000".equals(token));
    assertEquals(1, ((List<?>) first.get("items")).size());
    assertEquals(1, ((List<?>) first.get("data_units")).size());
    assertEquals(1, ((List<?>) first.get("symbols")).size());
    assertEquals(1, ((List<?>) first.get("comments")).size());
    assertEquals(1, ((List<?>) first.get("incoming_references")).size());
    assertEquals(0, ((List<?>) first.get("outgoing_references")).size());

    registry.dispatch(
        "listing_window.get",
        Map.of(
            "filter", Map.of("kind", "all"),
            "page", Map.of("limit", 80, "cursor", token),
            "scan",
                Map.of(
                    "range", Map.of("start", "ram:00401000"),
                    "timeout_ms", 15000)));
    assertEquals("ram:00401000", observedCursor.get());

    @SuppressWarnings("unchecked")
    Map<String, Object> batchResult =
        (Map<String, Object>)
            registry.dispatch(
                "batch.execute",
                Map.of(
                    "transaction_mode",
                    "per_item",
                    "items",
                    List.of(
                        Map.of(
                            "id",
                            "win",
                            "method",
                            "listing_window.get",
                            "arguments",
                            Map.of(
                                "filter", Map.of("kind", "all"),
                                "page", Map.of("limit", 80),
                                "scan",
                                    Map.of(
                                        "range", Map.of("start", "ram:00401000"),
                                        "timeout_ms", 15000))))));
    List<?> batchItems = (List<?>) batchResult.get("items");
    assertEquals(1, batchItems.size());
    Map<?, ?> firstBatchItem = (Map<?, ?>) batchItems.getFirst();
    assertEquals("win", firstBatchItem.get("id"));
    assertNotNull(firstBatchItem.get("result"));
  }

  @Test
  void controlFlowGraphGetValidatesSelectorAndProjectsFields() throws Exception {
    ControlFlowGraphResource graph =
        new ControlFlowGraphResource(
            "ram:00401000",
            "_ZN4demo3runEi",
            "Global",
            "demo::run(int)",
            new FunctionResource.Body("ram:00401000", "ram:00401005", 6L),
            true,
            0,
            List.of(
                new ControlFlowGraphResource.BlockResource(
                    "ram:00401000",
                    List.of(
                        new ControlFlowGraphResource.BlockInstructionResource("ram:00401000", 5),
                        new ControlFlowGraphResource.BlockInstructionResource("ram:00401005", 1)))),
            List.of(
                new ControlFlowGraphResource.NodeResource(
                    "block:0",
                    "block",
                    "ram:00401000",
                    "ram:00401000",
                    List.of("CALL 0x00402000", "RET"))),
            List.of(),
            new ScanProgress(
                ScanProgress.Kind.ADDRESS,
                "ram:00401000",
                "ram:00401005",
                "ram:00401000",
                "ram:00401005",
                true,
                ScanProgress.StopReason.COMPLETED,
                2L));

    ApiRegistry registry =
        createRegistry(
            unusedHandler(),
            (method, args) -> {
              assertEquals("getControlFlowGraph", method);
              assertEquals(null, args[0]);
              assertEquals("ram:00401002", args[1]);
              assertEquals(2048, args[2]);
              assertEquals(25000, args[3]);
              return graph;
            },
            unusedHandler());

    @SuppressWarnings("unchecked")
    Map<String, Object> full =
        (Map<String, Object>)
            registry.dispatch(
                "control_flow_graph.get",
                Map.of(
                    "selector", Map.of("address", "ram:00401002"),
                    "max_instructions", 2048,
                    "scan", Map.of("timeout_ms", 25000)));
    assertEquals("ram:00401000", full.get("entry"));
    assertEquals("demo::run(int)", full.get("demangled_name"));
    assertEquals(true, full.get("has_body"));
    assertEquals(1, ((List<?>) full.get("blocks")).size());
    assertEquals(1, ((List<?>) full.get("nodes")).size());

    @SuppressWarnings("unchecked")
    Map<String, Object> projected =
        (Map<String, Object>)
            registry.dispatch(
                "control_flow_graph.get",
                Map.of(
                    "selector", Map.of("address", "ram:00401002"),
                    "max_instructions", 2048,
                    "scan", Map.of("timeout_ms", 25000),
                    "projection", Map.of("fields", List.of("name", "has_body"))));
    assertEquals(
        Map.of("entry", "ram:00401000", "name", "_ZN4demo3runEi", "has_body", true), projected);

    ApiException ambiguous =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "control_flow_graph.get",
                    Map.of(
                        "selector",
                        Map.of("entry", "ram:00401000", "address", "ram:00401002"))));
    assertEquals(400, ambiguous.status());
  }

  @Test
  void referenceContextListSupportsTargetFiltersCallerSummaryAndPagination() throws Exception {
    ReferenceContextResource fromFn =
        new ReferenceContextResource(
            "ram:00401010",
            "ram:00402000",
            "UNCONDITIONAL_CALL",
            0,
            true,
            "ANALYSIS",
            "ram:00401010",
            new ReferenceContextResource.CallerSummary(
                "ram:00401000", "_ZN4demo6callerEv", "Global", "demo::caller()"));
    ReferenceContextResource fromData =
        new ReferenceContextResource(
            "ram:00403000", "ram:00402000", "DATA", 0, true, "IMPORTED", null, null);

    ApiRegistry registry =
        createRegistry(
            unusedHandler(),
            unusedHandler(),
            (method, args) -> {
              assertEquals("listReferenceContext", method);
              assertEquals(null, args[0]);
              assertEquals("ram:00402000", args[1]);
              assertEquals(null, args[2]);
              assertEquals("UNCONDITIONAL_CALL", args[3]);
              AddressScanOptions scan = (AddressScanOptions) args[4];
              assertEquals(12000, scan.timeoutMs());
              return Page.scanned(
                  List.of(fromData, fromFn),
                  (Integer) args[5],
                  "[\"ram:00403000\",\"ram:00402000\",\"DATA\",0]",
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00402000",
                      "ram:00402000",
                      "ram:00401010",
                      "ram:00403000",
                      false,
                      ScanProgress.StopReason.LIMIT,
                      3L));
            });

    @SuppressWarnings("unchecked")
    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "reference_context.list",
                Map.of(
                    "filter",
                        Map.of("entry", "ram:00402000", "type", "UNCONDITIONAL_CALL"),
                    "page", Map.of("limit", 2),
                    "scan", Map.of("timeout_ms", 12000)));

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(2, items.size());
    assertEquals("ram:00401010", items.get(0).get("from"));
    assertEquals("ram:00401010", items.get(0).get("call_site"));
    assertEquals(
        Map.of(
            "entry", "ram:00401000",
            "name", "_ZN4demo6callerEv",
            "namespace", "Global",
            "demangled_name", "demo::caller()"),
        items.get(0).get("caller"));
    assertEquals("ram:00403000", items.get(1).get("from"));
    assertFalse(items.get(1).containsKey("caller"));
    assertFalse(items.get(1).containsKey("call_site"));
    assertNotNull(response.get("next_cursor"));

    ApiException emptyFilter =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("reference_context.list", Map.of("filter", Map.of())));
    assertEquals(400, emptyFilter.status());
  }

  private static ApiRegistry createRegistry(
      Handler listingHandler, Handler functionHandler, Handler referenceHandler) {
    ListingService listing = proxy(ListingService.class, listingHandler);
    FunctionService functions = proxy(FunctionService.class, functionHandler);
    ReferenceService references = proxy(ReferenceService.class, referenceHandler);
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
            unused(MemoryService.class),
            listing,
            functions,
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static Handler unusedHandler() {
    return (method, args) -> {
      throw new AssertionError("Unexpected method: " + method);
    };
  }

  private static <T> T unused(Class<T> type) {
    return proxy(type, unusedHandler());
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
