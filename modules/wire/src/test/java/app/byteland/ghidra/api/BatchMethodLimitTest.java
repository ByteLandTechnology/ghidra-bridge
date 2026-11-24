package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
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
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class BatchMethodLimitTest {
  private static final long NANOS_PER_MS = 1_000_000L;
  private static final String HEX_64K = "aa".repeat(65_536);

  @Test
  void memoryReadBatchFailsBeforeExceedingEightMiBAndStopsRemainingItems() throws Exception {
    AtomicInteger readCalls = new AtomicInteger();
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("readMemoryRange", method);
              readCalls.incrementAndGet();
              return new MemoryResource(
                  "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, HEX_64K, 65_536));
            });
    ApiRegistry registry = registryWith(memory, unused(ListingService.class),
        unused(DecompilationService.class), unused(CommentService.class),
        passthroughTransactions(new AtomicBoolean(), new AtomicBoolean()), System::nanoTime);

    List<Map<String, Object>> validMediumItems = memoryReadItems(62);
    Object validResult = registry.dispatch("batch.execute", Map.of("items", validMediumItems));
    int serializedValidBytes =
        JsonUtil.toJson(validResult).getBytes(StandardCharsets.UTF_8).length;
    assertTrue(serializedValidBytes <= BatchMethod.MAX_RESPONSE_BYTES);
    assertEquals(62, readCalls.get());

    readCalls.set(0);
    List<Map<String, Object>> oversizedItems = memoryReadItems(BatchMethod.MAX_ITEMS);
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("batch.execute", Map.of("items", oversizedItems)));

    assertEquals(413, error.status());
    assertEquals("response_too_large", error.error().code());
    assertEquals("/items", error.error().target());
    assertEquals("m-63", error.error().details().get("failed_item"));
    assertEquals(BatchMethod.MAX_RESPONSE_BYTES, error.error().details().get("max_bytes"));
    // Must stop immediately at item 64 (m-63) rather than executing all 1,000 items.
    assertEquals(64, readCalls.get());
  }

  @Test
  void perItemErrorRowsAlsoEnforceCumulativeSizeLimitAndStopEarly() {
    AtomicInteger calls = new AtomicInteger();
    MemoryService failingMemory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              calls.incrementAndGet();
              throw new IllegalArgumentException("bad-range-" + "x".repeat(400));
            });
    BridgeServices services =
        bridgeServices(
            failingMemory,
            unused(ListingService.class),
            unused(DecompilationService.class),
            unused(CommentService.class),
            passthroughTransactions(new AtomicBoolean(), new AtomicBoolean()));
    ApiRegistry baseRegistry = new ApiRegistry(services, "test", Map::of, () -> {});
    Map<String, ApiMethod<Map<String, Object>, Object>> methods = new java.util.LinkedHashMap<>();
    for (ApiMethod<Map<String, Object>, Object> method : baseRegistry.methods()) {
      methods.put(method.name(), method);
    }
    BatchMethod smallCapBatch =
        new BatchMethod(
            methods,
            new BatchMethod.BatchRuntime() {
              @Override
              public Object invokeDecoded(
                  ApiMethod<Map<String, Object>, Object> method,
                  Map<String, Object> request,
                  boolean ownTransaction)
                  throws Exception {
                return method.invokeDecoded(request);
              }

              @Override
              public <T> T inTransaction(TransactionRunner.Operation<T> operation) {
                return services.transactionRunner().run(operation);
              }
            },
            System::nanoTime,
            1_024,
            BatchMethod.MAX_DURATION_MS);

    List<Map<String, Object>> items = memoryReadItems(20);
    ApiException error =
        assertThrows(
            ApiException.class,
            () -> smallCapBatch.registration().handler().handle(Map.of("items", items)));
    assertEquals(413, error.status());
    assertEquals("response_too_large", error.error().code());
    assertTrue(calls.get() < 5, "Expected remaining items to stop early, got " + calls.get());
  }

  @Test
  void allOrNoneRollsBackTransactionWhenResponseSizeExceedsLimit() {
    AtomicBoolean committed = new AtomicBoolean();
    AtomicBoolean rolledBack = new AtomicBoolean();
    AtomicInteger commentMutations = new AtomicInteger();
    AtomicInteger memoryReads = new AtomicInteger();

    CommentService comments =
        proxy(
            CommentService.class,
            (method, args) -> {
              if ("setComment".equals(method)) {
                commentMutations.incrementAndGet();
                return null;
              }
              assertEquals("listComments", method);
              return Page.of(
                  List.of(new CommentResource("ram:00100000", CommentResource.Type.EOL, "mutated")),
                  2,
                  null);
            });
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              memoryReads.incrementAndGet();
              return new MemoryResource(
                  "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, HEX_64K, 65_536));
            });

    ApiRegistry registry =
        registryWith(
            memory,
            unused(ListingService.class),
            unused(DecompilationService.class),
            comments,
            passthroughTransactions(committed, rolledBack),
            System::nanoTime);

    List<Map<String, Object>> items = new ArrayList<>();
    items.add(
        Map.of(
            "id",
            "c-0",
            "method",
            "comment.upsert",
            "arguments",
            Map.of(
                "resource",
                Map.of("address", "ram:00100000", "type", "eol", "text", "mutated"))));
    items.addAll(memoryReadItems(70));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.execute",
                    Map.of("transaction_mode", "all_or_none", "items", items)));

    assertEquals(409, error.status());
    assertEquals("batch_rolled_back", error.error().code());
    assertEquals("m-63", error.error().details().get("failed_item"));
    @SuppressWarnings("unchecked")
    Map<String, Object> cause = (Map<String, Object>) error.error().details().get("cause");
    assertEquals(413, cause.get("status"));
    assertEquals("response_too_large", cause.get("code"));
    assertEquals(1, commentMutations.get());
    assertEquals(64, memoryReads.get());
    assertFalse(committed.get());
    assertTrue(rolledBack.get());
  }

  @Test
  void scanAndDecompilationClampTimeoutToRemainingBatchTimeAndExpireAtDeadline() throws Exception {
    AtomicLong fakeNanos = new AtomicLong(1_000_000_000L);
    List<Integer> observedScanTimeouts = new ArrayList<>();
    List<Integer> observedDecompileTimeouts = new ArrayList<>();

    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              assertEquals("listCodeUnits", method);
              AddressScanOptions scan = (AddressScanOptions) args[0];
              observedScanTimeouts.add(scan.timeoutMs());
              fakeNanos.addAndGet(29_980L * NANOS_PER_MS);
              CodeUnitResource unit =
                  new CodeUnitResource(
                      "ram:00100000",
                      CodeUnitResource.Kind.INSTRUCTION,
                      1,
                      new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                      "NOP",
                      "NOP",
                      List.of(),
                      null);
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      scan.start(),
                      scan.end(),
                      "ram:00100000",
                      "ram:00100000",
                      false,
                      ScanProgress.StopReason.TIMEOUT,
                      scan.timeoutMs());
              return Page.scanned(List.of(unit), 10, "ram:00100000", progress);
            });

    DecompilationService decompilation =
        proxy(
            DecompilationService.class,
            (method, args) -> {
              assertEquals("decompileFunction", method);
              Integer timeoutMs = (Integer) args[2];
              observedDecompileTimeouts.add(timeoutMs);
              fakeNanos.addAndGet(50L * NANOS_PER_MS);
              return new DecompilationResource(
                  "ram:00100000",
                  "func",
                  DecompilationResource.Format.TEXT,
                  true,
                  timeoutMs,
                  "void func(void) {}\n",
                  null,
                  null,
                  null,
                  null,
                  List.of());
            });

    ApiRegistry registry =
        registryWith(
            unused(MemoryService.class),
            listing,
            decompilation,
            unused(CommentService.class),
            passthroughTransactions(new AtomicBoolean(), new AtomicBoolean()),
            fakeNanos::get);

    List<Map<String, Object>> items =
        List.of(
            scanItem("scan-0", 100),
            scanItem("scan-1", 5_000),
            decompileItem("dec-0", 30_000),
            scanItem("scan-2", 100));

    ApiException error =
        assertThrows(
            ApiException.class, () -> registry.dispatch("batch.execute", Map.of("items", items)));

    assertEquals(408, error.status());
    assertEquals("operation_timed_out", error.error().code());
    assertEquals("/items", error.error().target());
    assertEquals("scan-2", error.error().details().get("failed_item"));
    assertEquals(BatchMethod.MAX_DURATION_MS, error.error().details().get("timeout_ms"));
    // scan-0 had 60,000 ms remaining -> clamped to 100 ms.
    // scan-1 had 30,020 ms remaining -> clamped to 5,000 ms.
    // dec-0 had 40 ms remaining -> clamped to 40 ms (even below public 100 ms minimum!).
    // scan-2 had -10 ms remaining -> aborted before execution!
    assertEquals(List.of(100, 5_000), observedScanTimeouts);
    assertEquals(List.of(40), observedDecompileTimeouts);
    assertEquals(30_000, BatchMethod.clampTimeoutMs(30_000));
  }

  @Test
  void allOrNoneRollsBackOnDeadlineAndInterruptionStopsRemainingItems() {
    AtomicLong fakeNanos = new AtomicLong(5_000_000L);
    AtomicBoolean committed = new AtomicBoolean();
    AtomicBoolean rolledBack = new AtomicBoolean();
    AtomicInteger commentCalls = new AtomicInteger();

    CommentService comments =
        proxy(
            CommentService.class,
            (method, args) -> {
              if ("setComment".equals(method)) {
                commentCalls.incrementAndGet();
                return null;
              }
              assertEquals("listComments", method);
              CommentService.CommentQuery query = (CommentService.CommentQuery) args[0];
              if (commentCalls.get() == 1) {
                fakeNanos.addAndGet(BatchMethod.MAX_DURATION_MS * NANOS_PER_MS);
              }
              return Page.of(
                  List.of(
                      new CommentResource(
                          query.scan().start(), CommentResource.Type.EOL, "note")),
                  2,
                  null);
            });

    ApiRegistry registry =
        registryWith(
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(DecompilationService.class),
            comments,
            passthroughTransactions(committed, rolledBack),
            fakeNanos::get);

    List<Map<String, Object>> batchItems =
        List.of(
            Map.of(
                "id",
                "c-0",
                "method",
                "comment.upsert",
                "arguments",
                Map.of(
                    "resource",
                    Map.of("address", "ram:00100000", "type", "eol", "text", "first"))),
            Map.of(
                "id",
                "c-1",
                "method",
                "comment.upsert",
                "arguments",
                Map.of(
                    "resource",
                    Map.of("address", "ram:00100001", "type", "eol", "text", "second"))));

    ApiException rollbackError =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.execute",
                    Map.of("transaction_mode", "all_or_none", "items", batchItems)));
    assertEquals(409, rollbackError.status());
    assertEquals("batch_rolled_back", rollbackError.error().code());
    assertEquals("c-1", rollbackError.error().details().get("failed_item"));
    @SuppressWarnings("unchecked")
    Map<String, Object> cause = (Map<String, Object>) rollbackError.error().details().get("cause");
    assertEquals(408, cause.get("status"));
    assertEquals("operation_timed_out", cause.get("code"));
    assertEquals(1, commentCalls.get());
    assertFalse(committed.get());
    assertTrue(rolledBack.get());

    // Verify Thread.currentThread().isInterrupted() stops remaining items immediately.
    AtomicInteger interruptedCalls = new AtomicInteger();
    CommentService interruptingComments =
        proxy(
            CommentService.class,
            (method, args) -> {
              if ("setComment".equals(method)) {
                interruptedCalls.incrementAndGet();
                Thread.currentThread().interrupt();
                return null;
              }
              assertEquals("listComments", method);
              CommentService.CommentQuery query = (CommentService.CommentQuery) args[0];
              return Page.of(
                  List.of(
                      new CommentResource(
                          query.scan().start(), CommentResource.Type.EOL, "interrupted")),
                  2,
                  null);
            });
    ApiRegistry interruptRegistry =
        registryWith(
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(DecompilationService.class),
            interruptingComments,
            passthroughTransactions(new AtomicBoolean(), new AtomicBoolean()),
            System::nanoTime);

    try {
      ApiException interruptedError =
          assertThrows(
              ApiException.class,
              () -> interruptRegistry.dispatch("batch.execute", Map.of("items", batchItems)));
      assertEquals(408, interruptedError.status());
      assertEquals("operation_timed_out", interruptedError.error().code());
      assertEquals(1, interruptedCalls.get());
    } finally {
      Thread.interrupted();
    }
  }

  private static List<Map<String, Object>> memoryReadItems(int count) {
    List<Map<String, Object>> items = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      items.add(
          Map.of(
              "id",
              "m-" + i,
              "method",
              "memory.read",
              "arguments",
              Map.of(
                  "selector",
                  Map.of("address", "ram:00100000"),
                  "length",
                  65_536,
                  "encoding",
                  "hex")));
    }
    return items;
  }

  private static Map<String, Object> scanItem(String id, int timeoutMs) {
    return Map.of(
        "id",
        id,
        "method",
        "code_unit.list",
        "arguments",
        Map.of(
            "scan",
            Map.of(
                "range",
                Map.of("start", "ram:00100000", "end", "ram:7fffffff"),
                "timeout_ms",
                timeoutMs),
            "page",
            Map.of("limit", 10)));
  }

  private static Map<String, Object> decompileItem(String id, int timeoutMs) {
    return Map.of(
        "id",
        id,
        "method",
        "decompilation.get",
        "arguments",
        Map.of(
            "selector",
            Map.of("entry", "ram:00100000"),
            "scan",
            Map.of("timeout_ms", timeoutMs)));
  }

  private static TransactionRunner passthroughTransactions(
      AtomicBoolean committed, AtomicBoolean rolledBack) {
    return new TransactionRunner() {
      @Override
      public <T> T run(Operation<T> operation) {
        try {
          T result = operation.execute();
          committed.set(true);
          return result;
        } catch (RuntimeException runtimeError) {
          rolledBack.set(true);
          throw runtimeError;
        } catch (Exception checked) {
          rolledBack.set(true);
          throw new RuntimeException(checked);
        }
      }
    };
  }

  private static ApiRegistry registryWith(
      MemoryService memory,
      ListingService listing,
      DecompilationService decompilation,
      CommentService comments,
      TransactionRunner transactions,
      java.util.function.LongSupplier nanoTime) {
    return new ApiRegistry(
        bridgeServices(memory, listing, decompilation, comments, transactions),
        "test-session",
        Map::of,
        () -> {},
        nanoTime);
  }

  private static BridgeServices bridgeServices(
      MemoryService memory,
      ListingService listing,
      DecompilationService decompilation,
      CommentService comments,
      TransactionRunner transactions) {
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
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        comments,
        unused(ReferenceService.class),
        memory,
        listing,
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysis,
        decompilation,
        unused(SymbolService.class),
        unused(DataTypeService.class),
        transactions,
        "test-program");
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) return null;
          throw new AssertionError("Unexpected service call: " + type.getSimpleName() + "." + method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> type.getSimpleName() + "Proxy";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(method.getName(), args);
            }));
  }
}
