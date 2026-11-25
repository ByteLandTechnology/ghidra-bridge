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
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
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
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
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
    for (ApiCatalog.MethodDescriptor descriptor : baseRegistry.methodCatalog().methods()) {
      methods.put(descriptor.name(), baseRegistry.method(descriptor.name()));
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
              if ("setFlowOverrides".equals(method)) {
                return null;
              }
              if ("getFlowOverrides".equals(method)) {
                AddressScanOptions scan = (AddressScanOptions) args[2];
                observedScanTimeouts.add(scan.timeoutMs());
                return Page.of(List.of(), 1_000, null);
              }
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
            Map.of(
                "id",
                "flow-0",
                "method",
                "flow_override.patch",
                "arguments",
                Map.of(
                    "selector",
                    Map.of("kind", "address", "address", "ram:00100000"),
                    "patch",
                    Map.of("flow_override", "return"))),
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
    // flow-0 had 40 ms remaining -> default 5,000 ms scan clamped to 40 ms.
    // dec-0 had 40 ms remaining -> clamped to 40 ms (below public 100 ms minimum).
    // scan-2 had -10 ms remaining -> stopped before execution.
    assertEquals(List.of(100, 5_000, 40), observedScanTimeouts);
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

  @Test
  void supportsLargeGhidraLspAndMcpBatchWorkloadsWithinDefaultLimits() throws Exception {
    AtomicLong fakeNanos = new AtomicLong(10_000_000_000L);
    List<Integer> observedFunctionTimeouts = new ArrayList<>();

    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              fakeNanos.addAndGet(5L * NANOS_PER_MS);
              return switch (method) {
                case "getProgram" ->
                    new ProgramResource(
                        "firmware.elf",
                        "/opt/firmware.elf",
                        "Executable and Linking Format (ELF)",
                        "ram:00100000",
                        "ram:00100000",
                        "ram:01ffffff",
                        "x86:LE:64:default",
                        "gcc",
                        Instant.parse("2026-01-01T00:00:00Z"),
                        Instant.parse("2026-01-02T00:00:00Z"),
                        25_000L,
                        60_000L);
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
                                "ram:0000000000000000",
                                "ram:ffffffffffffffff",
                                true),
                            new AddressSpaceResource(
                                "EXTERNAL",
                                AddressSpaceResource.Kind.EXTERNAL,
                                64,
                                "EXTERNAL:0000000000000000",
                                "EXTERNAL:ffffffffffffffff",
                                false)),
                        1_000,
                        null);
                default -> throw new AssertionError("Unexpected method: " + method);
              };
            });

    MemoryService memoryService =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("listMemoryBlocks", method);
              fakeNanos.addAndGet(10L * NANOS_PER_MS);
              List<MemoryBlockResource> blocks = new ArrayList<>(32);
              for (int i = 0; i < 32; i++) {
                String start = String.format("ram:%08x", 0x0010_0000 + i * 0x10_000);
                String end = String.format("ram:%08x", 0x0010_ffff + i * 0x10_000);
                blocks.add(
                    new MemoryBlockResource(
                        ".section_" + i,
                        start,
                        end,
                        65_536L,
                        true,
                        i % 2 == 0,
                        i < 8,
                        true,
                        false,
                        false,
                        MemoryBlockResource.Kind.DEFAULT,
                        null));
              }
              return Page.of(blocks, 1_000, null);
            });

    FunctionService functionService =
        proxy(
            FunctionService.class,
            (method, args) -> {
              assertEquals("listFunctions", method);
              FunctionService.FunctionQuery query = (FunctionService.FunctionQuery) args[0];
              observedFunctionTimeouts.add(query.scan().timeoutMs());
              fakeNanos.addAndGet(query.scan().timeoutMs() * NANOS_PER_MS);
              List<FunctionResource> functions = new ArrayList<>(1_000);
              for (int i = 0; i < 1_000; i++) {
                String entry = String.format("ram:%08x", 0x0010_0000 + i * 0x40);
                functions.add(
                    new FunctionResource(
                        entry,
                        "_ZN6engine9subsystem12process_node_" + i + "ERKNS_7ContextE",
                        "engine::subsystem",
                        new FunctionResource.Body(entry, entry, 64L),
                        "void process_node(void)",
                        null,
                        null,
                        1,
                        "__stdcall",
                        null,
                        null,
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
                        "engine::subsystem::process_node_" + i + "(engine::Context const&)"));
              }
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00100000",
                      "ram:01ffffff",
                      "ram:0010f9c0",
                      "ram:0010fa00",
                      false,
                      ScanProgress.StopReason.TIMEOUT,
                      query.scan().timeoutMs());
              return Page.scanned(functions, query.limit(), "ram:0010fa00", progress);
            });

    AddressService addressService =
        proxy(
            AddressService.class,
            (method, args) -> {
              assertEquals("resolveAddress", method);
              String addr = (String) args[0];
              return new AddressResource(
                  addr,
                  true,
                  true,
                  new AddressResource.MemoryBlockSummary(
                      ".text", "ram:00100000", "ram:009fffff", 0x900000L, true, false, true),
                  new AddressResource.FunctionSummary("ram:00100000", "dispatch_table"),
                  new AddressResource.SymbolSummary("sym-1", "loc_" + addr.substring(4), "Label"),
                  new AddressResource.CodeUnitSummary(addr, addr));
            });

    ReferenceService referenceService =
        proxy(
            ReferenceService.class,
            (method, args) -> {
              assertEquals("listReferences", method);
              String from = (String) args[0];
              String to = (String) args[1];
              String direction = (String) args[3];
              int limit = (Integer) args[4];
              int count = limit == 100 ? 4 : limit;
              List<ReferenceResource> refs = new ArrayList<>(count);
              for (int i = 0; i < count; i++) {
                String peer = String.format("ram:%08x", 0x0020_0000 + i * 4);
                refs.add(
                    new ReferenceResource(
                        "from".equals(direction) ? from : peer,
                        "to".equals(direction) ? to : peer,
                        "UNCONDITIONAL_JUMP",
                        0,
                        i == 0,
                        "ANALYSIS"));
              }
              return Page.of(refs, limit, null);
            });

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
    BridgeServices services =
        new BridgeServices(
            programService,
            addressService,
            unused(CommentService.class),
            referenceService,
            memoryService,
            unused(ListingService.class),
            functionService,
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            passthroughTransactions(new AtomicBoolean(), new AtomicBoolean()),
            "firmware-program");
    ApiRegistry registry =
        new ApiRegistry(services, "lsp-session", Map::of, () -> {}, fakeNanos::get);

    // 1. ghidra-lsp meta.rs batch: 4 metadata calls + 1,000 projected functions with 60s timeout.
    List<Map<String, Object>> metaItems =
        List.of(
            Map.of("id", "program", "method", "program.get", "arguments", Map.of()),
            Map.of("id", "language", "method", "program_language.get", "arguments", Map.of()),
            Map.of(
                "id",
                "blocks",
                "method",
                "memory_block.list",
                "arguments",
                Map.of("page", Map.of("limit", 1_000))),
            Map.of(
                "id",
                "spaces",
                "method",
                "address_space.list",
                "arguments",
                Map.of("page", Map.of("limit", 1_000))),
            Map.of(
                "id",
                "functions",
                "method",
                "function.list",
                "arguments",
                Map.of(
                    "page",
                    Map.of("limit", 1_000),
                    "scan",
                    Map.of("timeout_ms", 60_000),
                    "projection",
                    Map.of(
                        "fields",
                        List.of("entry", "name", "namespace", "demangled_name")))));
    Object metaResult =
        registry.dispatch(
            "batch.execute", Map.of("transaction_mode", "per_item", "items", metaItems));
    int metaBytes = JsonUtil.toJson(metaResult).getBytes(StandardCharsets.UTF_8).length;
    assertEquals(List.of(59_975), observedFunctionTimeouts);
    assertTrue(metaBytes < 512 * 1024, "Expected meta batch < 512 KiB, got " + metaBytes);

    // 2. ghidra-lsp listing_fetch.rs xref wave: 64 incoming (limit 25) + 64 outgoing (limit 10).
    List<Map<String, Object>> xrefWaveItems = new ArrayList<>(128);
    for (int i = 0; i < 64; i++) {
      String addr = String.format("ram:%08x", 0x0010_0000 + i * 4);
      xrefWaveItems.add(
          Map.of(
              "id",
              "in_" + i,
              "method",
              "reference.list",
              "arguments",
              Map.of(
                  "filter",
                  Map.of("to", addr, "direction", "to"),
                  "page",
                  Map.of("limit", 25))));
      xrefWaveItems.add(
          Map.of(
              "id",
              "out_" + i,
              "method",
              "reference.list",
              "arguments",
              Map.of(
                  "filter",
                  Map.of("from", addr, "direction", "from"),
                  "page",
                  Map.of("limit", 10))));
    }
    Object xrefResult =
        registry.dispatch(
            "batch.execute", Map.of("transaction_mode", "per_item", "items", xrefWaveItems));
    int xrefBytes = JsonUtil.toJson(xrefResult).getBytes(StandardCharsets.UTF_8).length;
    assertTrue(xrefBytes < 512 * 1024, "Expected xref wave < 512 KiB, got " + xrefBytes);

    // 3. ghidra-lsp cfg.rs 1,000-item chunks: address.resolve x 1,000 and reference.list x 1,000.
    List<Map<String, Object>> resolveChunk = new ArrayList<>(BatchMethod.MAX_ITEMS);
    List<Map<String, Object>> cfgRefChunk = new ArrayList<>(BatchMethod.MAX_ITEMS);
    for (int i = 0; i < BatchMethod.MAX_ITEMS; i++) {
      String addr = String.format("ram:%08x", 0x0010_0000 + i * 4);
      resolveChunk.add(
          Map.of(
              "id",
              "r" + i,
              "method",
              "address.resolve",
              "arguments",
              Map.of("selector", Map.of("address", addr))));
      cfgRefChunk.add(
          Map.of(
              "id",
              "q" + i,
              "method",
              "reference.list",
              "arguments",
              Map.of("filter", Map.of("from", addr, "direction", "from"))));
    }
    Object resolveResult =
        registry.dispatch(
            "batch.execute", Map.of("transaction_mode", "per_item", "items", resolveChunk));
    int resolveBytes = JsonUtil.toJson(resolveResult).getBytes(StandardCharsets.UTF_8).length;
    assertTrue(
        resolveBytes < 1024 * 1024, "Expected 1,000 address.resolve < 1 MiB, got " + resolveBytes);

    Object cfgRefResult =
        registry.dispatch(
            "batch.execute", Map.of("transaction_mode", "per_item", "items", cfgRefChunk));
    int cfgRefBytes = JsonUtil.toJson(cfgRefResult).getBytes(StandardCharsets.UTF_8).length;
    assertTrue(
        cfgRefBytes < 2 * 1024 * 1024,
        "Expected 1,000 CFG reference.list < 2 MiB, got " + cfgRefBytes);
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
