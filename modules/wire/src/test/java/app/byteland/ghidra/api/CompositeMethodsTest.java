package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
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
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.listing.ListingWindowResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
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
                    "42",
                    "entry_label",
                    "ram:00401000",
                    "Global",
                    "Label",
                    "USER_DEFINED",
                    true,
                    null)),
            List.of(),
            List.of(new CommentResource("ram:00401000", CommentResource.Type.EOL, "return site")),
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
            });

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

  private static ApiRegistry createRegistry(Handler listingHandler) {
    ListingService listing = proxy(ListingService.class, listingHandler);
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
            unused(ReferenceService.class),
            unused(MemoryService.class),
            listing,
            unused(FunctionService.class),
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
