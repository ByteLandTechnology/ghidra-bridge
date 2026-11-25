package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentDispatcherTest {

  @Test
  @DisplayName("Initializes session ID directly without AgentConfig and reports it in session.get")
  void initializesSessionIdDirectly() throws Exception {
    AtomicInteger closeCount = new AtomicInteger();
    BridgeServices services = stubServices("sample.elf", closeCount);

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "  mcp-session-42  ")) {
      assertEquals("sample.elf", dispatcher.getProgramName());
      assertFalse(dispatcher.isShuttingDown());

      @SuppressWarnings("unchecked")
      Map<String, Object> activeInfo =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("mcp-session-42", activeInfo.get("id"));
      assertEquals("active", activeInfo.get("status"));
      assertEquals("sample.elf", activeInfo.get("program_name"));

      dispatcher.dispatch("session.shutdown", Map.of());
      assertTrue(dispatcher.isShuttingDown());

      @SuppressWarnings("unchecked")
      Map<String, Object> shuttingDownInfo =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("mcp-session-42", shuttingDownInfo.get("id"));
      assertEquals("shutting_down", shuttingDownInfo.get("status"));
      assertEquals("sample.elf", shuttingDownInfo.get("program_name"));
    }

    assertEquals(2, closeCount.get());
  }

  @Test
  @DisplayName("Delegates AgentConfig constructor to sessionId constructor")
  void delegatesAgentConfigConstructor() throws Exception {
    BridgeServices services = stubServices("ws-target.bin", new AtomicInteger());
    AgentConfig serverConfig =
        AgentConfig.fromMap(
            Map.of("host", "127.0.0.1", "port", "8765", "session_id", "ws-server-session"));

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, serverConfig)) {
      @SuppressWarnings("unchecked")
      Map<String, Object> info =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("ws-server-session", info.get("id"));
      assertEquals("active", info.get("status"));
      assertEquals("ws-target.bin", info.get("program_name"));
    }

    AgentConfig outboundConfig =
        AgentConfig.fromMap(
            Map.of("ws_url", "ws://127.0.0.1:8765/ws/agent", "session_id", "ws-outbound-session"));

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, outboundConfig)) {
      @SuppressWarnings("unchecked")
      Map<String, Object> info =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("ws-outbound-session", info.get("id"));
    }
  }

  @Test
  @DisplayName("Rejects null or blank sessionId and null constructor arguments")
  void rejectsInvalidConstructorInputs() {
    BridgeServices services = stubServices("sample.elf", new AtomicInteger());
    AgentConfig validConfig =
        AgentConfig.fromMap(Map.of("host", "127.0.0.1", "port", "8765", "session_id", "demo"));

    assertThrows(
        IllegalArgumentException.class, () -> new AgentDispatcher(services, (String) null));
    assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, ""));
    assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, "   \t\n "));
    assertThrows(NullPointerException.class, () -> new AgentDispatcher(null, "demo"));
    assertThrows(
        NullPointerException.class, () -> new AgentDispatcher(services, (AgentConfig) null));
    assertThrows(NullPointerException.class, () -> new AgentDispatcher(null, validConfig));
  }

  @Test
  @DisplayName("Rejects dispatch after close")
  void rejectsDispatchAfterClose() {
    BridgeServices services = stubServices("sample.elf", new AtomicInteger());
    AgentDispatcher dispatcher = new AgentDispatcher(services, "closed-session");
    dispatcher.close();

    assertThrows(IllegalStateException.class, () -> dispatcher.dispatch("session.get", Map.of()));
  }

  @Test
  @DisplayName("Bypasses sequenceLock for session.get, interface.get, and analysis.get during slow decompilation")
  void bypassesSequenceLockForMetadataAndAnalysisStatus() throws Exception {
    CountDownLatch decompEntered = new CountDownLatch(1);
    CountDownLatch releaseDecomp = new CountDownLatch(1);
    AtomicReference<AgentDispatcher> dispatcherRef = new AtomicReference<>();
    AtomicBoolean statusSawOuterLock = new AtomicBoolean(false);
    AtomicBoolean statusHeldLock = new AtomicBoolean(true);

    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (name, args) -> {
              if ("close".equals(name)) return null;
              assertEquals("getStatus", name);
              AgentDispatcher active = dispatcherRef.get();
              statusSawOuterLock.set(active.isSequenceLocked());
              statusHeldLock.set(active.isSequenceLockedByCurrentThread());
              return new AnalysisResource(
                  AnalysisResource.Kind.GHIDRA,
                  AnalysisResource.Status.IDLE,
                  true,
                  null,
                  null,
                  null,
                  null);
            });
    DecompilationService decompilation =
        proxy(
            DecompilationService.class,
            (name, args) -> {
              if ("close".equals(name)) return null;
              assertEquals("decompileFunction", name);
              assertTrue(dispatcherRef.get().isSequenceLockedByCurrentThread());
              decompEntered.countDown();
              try {
                assertTrue(releaseDecomp.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
              }
              return sampleDecompilation();
            });

    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            decompilation,
            unused(SymbolService.class),
            unused(DataTypeService.class),
            unexpectedTransactions(),
            "firmware.bin");

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "lock-free-session");
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      dispatcherRef.set(dispatcher);

      // Warm up codecs and method lookup paths once before latency measurement.
      dispatcher.dispatch("session.get", Map.of());
      dispatcher.dispatch("interface.get", Map.of());
      dispatcher.dispatch("analysis.get", Map.of());

      Future<Object> slowDecomp =
          executor.submit(
              () ->
                  dispatcher.dispatch(
                      "decompilation.get", Map.of("selector", Map.of("entry", "ram:00100000"))));
      assertTrue(decompEntered.await(5, TimeUnit.SECONDS));
      assertTrue(dispatcher.isSequenceLocked());

      int concurrency = 20;
      CountDownLatch startGate = new CountDownLatch(1);
      List<Future<Long>> sessionFutures = new ArrayList<>();
      List<Future<Long>> interfaceFutures = new ArrayList<>();
      List<Future<Long>> analysisFutures = new ArrayList<>();

      for (int i = 0; i < concurrency; i++) {
        sessionFutures.add(
            executor.submit(
                timedCall(
                    startGate,
                    () -> {
                      @SuppressWarnings("unchecked")
                      Map<String, Object> result =
                          (Map<String, Object>)
                              dispatcher.dispatch(
                                  "session.get",
                                  Map.of("projection", Map.of("fields", List.of("status"))));
                      assertEquals(Map.of("id", "lock-free-session", "status", "active"), result);
                      return result;
                    })));
        interfaceFutures.add(
            executor.submit(
                timedCall(
                    startGate,
                    () -> {
                      @SuppressWarnings("unchecked")
                      Map<String, Object> result =
                          (Map<String, Object>) dispatcher.dispatch("interface.get", Map.of());
                      assertEquals(56, ((List<?>) result.get("methods")).size());
                      return result;
                    })));
        analysisFutures.add(
            executor.submit(
                timedCall(
                    startGate,
                    () -> {
                      @SuppressWarnings("unchecked")
                      Map<String, Object> result =
                          (Map<String, Object>)
                              dispatcher.dispatch(
                                  "analysis.get",
                                  Map.of("projection", Map.of("fields", List.of("analyzed"))));
                      assertEquals(Map.of("kind", "ghidra", "analyzed", true), result);
                      return result;
                    })));
      }

      startGate.countDown();
      long maxAllowedMedianNanos = TimeUnit.MILLISECONDS.toNanos(5);
      assertTrue(medianNanos(sessionFutures) < maxAllowedMedianNanos);
      assertTrue(medianNanos(interfaceFutures) < maxAllowedMedianNanos);
      assertTrue(medianNanos(analysisFutures) < maxAllowedMedianNanos);
      assertFalse(slowDecomp.isDone());
      assertTrue(statusSawOuterLock.get());
      assertFalse(statusHeldLock.get());

      // Keep decompilation active for 200 ms total, then release and confirm completion.
      Thread.sleep(200);
      releaseDecomp.countDown();
      assertNotNull(slowDecomp.get(5, TimeUnit.SECONDS));
    }
  }

  @Test
  @DisplayName("Waits for lock-free dispatches inside DispatchBarrier before closing services")
  void waitsForInFlightLockFreeDispatchBeforeClose() throws Exception {
    CountDownLatch statusEntered = new CountDownLatch(1);
    CountDownLatch releaseStatus = new CountDownLatch(1);
    AtomicBoolean closedBeforeStatusFinished = new AtomicBoolean(false);
    AtomicBoolean serviceClosed = new AtomicBoolean(false);

    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (name, args) -> {
              if ("close".equals(name)) {
                serviceClosed.set(true);
                return null;
              }
              statusEntered.countDown();
              try {
                assertTrue(releaseStatus.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
              }
              if (serviceClosed.get()) {
                closedBeforeStatusFinished.set(true);
              }
              return new AnalysisResource(
                  AnalysisResource.Kind.GHIDRA,
                  AnalysisResource.Status.IDLE,
                  false,
                  null,
                  null,
                  null,
                  null);
            });

    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            closeableStub(DecompilationService.class, new AtomicInteger()),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            unexpectedTransactions(),
            "barrier.bin");

    AgentDispatcher dispatcher = new AgentDispatcher(services, "barrier-session");
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      Future<Object> statusCall =
          executor.submit(() -> dispatcher.dispatch("analysis.get", Map.of()));
      assertTrue(statusEntered.await(5, TimeUnit.SECONDS));

      Future<?> closeCall = executor.submit(dispatcher::close);
      Thread.sleep(25);
      assertFalse(closeCall.isDone());
      assertFalse(serviceClosed.get());

      releaseStatus.countDown();
      assertNotNull(statusCall.get(5, TimeUnit.SECONDS));
      closeCall.get(5, TimeUnit.SECONDS);
      assertTrue(serviceClosed.get());
      assertFalse(closedBeforeStatusFinished.get());
    }
  }

  @Test
  @DisplayName("Fails invalid method names, request schemas, and projections before sequenceLock")
  void failsInvalidRequestsWithoutWaitingOnSequenceLock() throws Exception {
    CountDownLatch decompEntered = new CountDownLatch(1);
    CountDownLatch releaseDecomp = new CountDownLatch(1);

    DecompilationService decompilation =
        proxy(
            DecompilationService.class,
            (name, args) -> {
              if ("close".equals(name)) return null;
              decompEntered.countDown();
              try {
                assertTrue(releaseDecomp.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
              }
              return sampleDecompilation();
            });

    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            closeableStub(AnalysisService.class, new AtomicInteger()),
            decompilation,
            unused(SymbolService.class),
            unused(DataTypeService.class),
            unexpectedTransactions(),
            "validation.bin");

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "validation-session");
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      Future<Object> slowDecomp =
          executor.submit(
              () ->
                  dispatcher.dispatch(
                      "decompilation.get", Map.of("selector", Map.of("entry", "ram:00100000"))));
      assertTrue(decompEntered.await(5, TimeUnit.SECONDS));

      CountDownLatch startGate = new CountDownLatch(1);
      List<Future<Long>> invalidFutures = new ArrayList<>();
      for (int i = 0; i < 20; i++) {
        final int mode = i % 5;
        invalidFutures.add(
            executor.submit(
                timedCall(
                    startGate,
                    () -> {
                      ApiException failure =
                          switch (mode) {
                            case 0 ->
                                assertThrows(
                                    ApiException.class, () -> dispatcher.dispatch("   ", Map.of()));
                            case 1 ->
                                assertThrows(
                                    ApiException.class,
                                    () -> dispatcher.dispatch("unknown.method", Map.of()));
                            case 2 ->
                                assertThrows(
                                    ApiException.class,
                                    () -> dispatcher.dispatch("memory.read", Map.of("length", 0)));
                            case 3 ->
                                assertThrows(
                                    ApiException.class,
                                    () ->
                                        dispatcher.dispatch(
                                            "program.get",
                                            Map.of(
                                                "projection",
                                                Map.of("fields", List.of("not_a_field")))));
                            default ->
                                assertThrows(
                                    ApiException.class,
                                    () ->
                                        dispatcher.dispatch(
                                            "batch.execute",
                                            Map.of(
                                                "items",
                                                List.of(
                                                    Map.of(
                                                        "id",
                                                        "bad-1",
                                                        "method",
                                                        "memory.read",
                                                        "arguments",
                                                        Map.of("length", -1))))));
                          };
                      assertEquals(mode == 1 ? 404 : 400, failure.error().status());
                      return failure;
                    })));
      }

      startGate.countDown();
      assertTrue(medianNanos(invalidFutures) < TimeUnit.MILLISECONDS.toNanos(5));
      assertFalse(slowDecomp.isDone());

      releaseDecomp.countDown();
      assertNotNull(slowDecomp.get(5, TimeUnit.SECONDS));
    }
  }

  @Test
  @DisplayName("Releases sequenceLock before JsonValueCodec validation and field projection")
  void encodesAndProjectsResponsesAfterReleasingSequenceLock() throws Exception {
    AtomicReference<AgentDispatcher> dispatcherRef = new AtomicReference<>();
    AtomicBoolean returnInvalidProgram = new AtomicBoolean(false);

    ProgramService programService =
        proxy(
            ProgramService.class,
            (name, args) -> {
              assertEquals("getProgram", name);
              assertTrue(dispatcherRef.get().isSequenceLockedByCurrentThread());
              return new ProgramResource(
                  returnInvalidProgram.get() ? null : "valid.elf",
                  "/bin/valid.elf",
                  "ELF",
                  "ram:00100000",
                  "ram:00100000",
                  "ram:00100fff",
                  "x86:LE:64:default",
                  "gcc",
                  Instant.EPOCH,
                  Instant.EPOCH,
                  1L,
                  2L);
            });

    BridgeServices services =
        new BridgeServices(
            programService,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            closeableStub(AnalysisService.class, new AtomicInteger()),
            closeableStub(DecompilationService.class, new AtomicInteger()),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            unexpectedTransactions(),
            "valid.elf");

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "post-lock-session")) {
      dispatcherRef.set(dispatcher);

      @SuppressWarnings("unchecked")
      Map<String, Object> projected =
          (Map<String, Object>)
              dispatcher.dispatch(
                  "program.get",
                  Map.of("projection", Map.of("fields", List.of("executable_format"))));
      assertEquals(Map.of("name", "valid.elf", "executable_format", "ELF"), projected);
      assertFalse(dispatcher.isSequenceLocked());

      returnInvalidProgram.set(true);
      ApiException invalidResponse =
          assertThrows(ApiException.class, () -> dispatcher.dispatch("program.get", Map.of()));
      assertEquals(500, invalidResponse.error().status());
      assertEquals("invalid_response", invalidResponse.error().code());
      assertFalse(dispatcher.isSequenceLocked());
    }
  }

  @Test
  @DisplayName("Serializes all 26 program reads, mutations, and batch executions in FIFO order")
  void serializesAllProgramReadsMutationsAndBatchesInOrder() throws Exception {
    AtomicReference<AgentDispatcher> dispatcherRef = new AtomicReference<>();
    AtomicBoolean probeMode = new AtomicBoolean(true);
    AtomicInteger lockedProbeCount = new AtomicInteger();
    AtomicInteger activeLockedCalls = new AtomicInteger();
    AtomicInteger maxConcurrentLockedCalls = new AtomicInteger();
    List<String> observedOrder = Collections.synchronizedList(new ArrayList<>());

    CountDownLatch firstEntered = new CountDownLatch(1);
    CountDownLatch releaseFirst = new CountDownLatch(1);

    Runnable recordLockedExecution =
        () -> {
          AgentDispatcher dispatcher = dispatcherRef.get();
          assertTrue(dispatcher.isSequenceLockedByCurrentThread());
          int concurrent = activeLockedCalls.incrementAndGet();
          maxConcurrentLockedCalls.accumulateAndGet(concurrent, Math::max);
          try {
            Thread.sleep(5);
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
          } finally {
            activeLockedCalls.decrementAndGet();
          }
        };

    DecompilationService decompilation =
        proxy(
            DecompilationService.class,
            (name, args) -> {
              if ("close".equals(name)) return null;
              assertTrue(dispatcherRef.get().isSequenceLockedByCurrentThread());
              if (probeMode.get()) {
                lockedProbeCount.incrementAndGet();
                throw new LockedProbeSignal(name);
              }
              firstEntered.countDown();
              try {
                assertTrue(releaseFirst.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
              }
              return sampleDecompilation();
            });

    BridgeServices services =
        serializedServices(
            dispatcherRef,
            probeMode,
            lockedProbeCount,
            recordLockedExecution,
            observedOrder,
            decompilation);

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "fifo-session");
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      dispatcherRef.set(dispatcher);

      // Verify method catalog counts: 56 methods total, 29 read-only = 3 lock-free + 26 program reads.
      List<String> readOnlyMethods =
          dispatcher.methodCatalog().methods().stream()
              .filter(descriptor -> "read-only".equals(descriptor.effectSummary()))
              .map(ApiCatalog.MethodDescriptor::name)
              .toList();
      assertEquals(29, readOnlyMethods.size());
      Set<String> lockFree = Set.of("interface.get", "session.get", "analysis.get");
      List<String> programReadMethods =
          readOnlyMethods.stream().filter(name -> !lockFree.contains(name)).toList();
      assertEquals(26, programReadMethods.size());

      // Dispatch all 26 program read methods and confirm every one holds sequenceLock.
      for (String readMethod : programReadMethods) {
        assertThrows(
            LockedProbeSignal.class,
            () -> dispatcher.dispatch(readMethod, sampleReadParams(readMethod)),
            readMethod);
      }
      assertEquals(26, lockedProbeCount.get());
      probeMode.set(false);

      // Hold sequenceLock in decompilation.get, then enqueue 5 diverse calls in strict arrival order:
      // two program reads, one metadata-only batch.execute, one transactional mutation, and program.save.
      Future<Object> holder =
          executor.submit(
              () ->
                  dispatcher.dispatch(
                      "decompilation.get", Map.of("selector", Map.of("entry", "ram:00100000"))));
      assertTrue(firstEntered.await(5, TimeUnit.SECONDS));

      List<Callable<Object>> queuedCalls =
          List.of(
              () -> dispatcher.dispatch("program.get", Map.of()),
              () ->
                  dispatcher.dispatch(
                      "memory.read",
                      Map.of("selector", Map.of("address", "ram:00100000"), "length", 4)),
              () ->
                  dispatcher.dispatch(
                      "batch.execute",
                      Map.of(
                          "items",
                          List.of(
                              Map.of(
                                  "id",
                                  "item-1",
                                  "method",
                                  "session.get",
                                  "arguments",
                                  Map.of()),
                              Map.of(
                                  "id",
                                  "item-2",
                                  "method",
                                  "analysis.get",
                                  "arguments",
                                  Map.of())))),
              () -> dispatcher.dispatch("symbol.demangle", Map.of()),
              () -> dispatcher.dispatch("program.save", Map.of()));

      List<Future<Object>> queuedFutures = new ArrayList<>();
      for (Callable<Object> call : queuedCalls) {
        CountDownLatch threadStarted = new CountDownLatch(1);
        queuedFutures.add(
            executor.submit(
                () -> {
                  threadStarted.countDown();
                  return call.call();
                }));
        assertTrue(threadStarted.await(5, TimeUnit.SECONDS));
        Thread.sleep(15);
      }

      assertEquals(0, observedOrder.size());
      releaseFirst.countDown();
      assertNotNull(holder.get(5, TimeUnit.SECONDS));
      for (Future<Object> future : queuedFutures) {
        assertNotNull(future.get(5, TimeUnit.SECONDS));
      }

      assertEquals(1, maxConcurrentLockedCalls.get());
      assertEquals(
          List.of(
              "program.get", "memory.read", "batch.analysis", "symbol.demangle", "program.save"),
          observedOrder);
    }
  }

  private static BridgeServices serializedServices(
      AtomicReference<AgentDispatcher> dispatcherRef,
      AtomicBoolean probeMode,
      AtomicInteger lockedProbeCount,
      Runnable recordLockedExecution,
      List<String> observedOrder,
      DecompilationService decompilation) {
    ProxyHandler probeHandler =
        (name, args) -> {
          assertTrue(dispatcherRef.get().isSequenceLockedByCurrentThread());
          lockedProbeCount.incrementAndGet();
          throw new LockedProbeSignal(name);
        };

    ProgramService programService =
        proxy(
            ProgramService.class,
            (name, args) -> {
              if (probeMode.get()) {
                return probeHandler.invoke(name, args);
              }
              recordLockedExecution.run();
              return switch (name) {
                case "getProgram" -> {
                  observedOrder.add("program.get");
                  yield new ProgramResource(
                      "sample.elf",
                      "/bin/sample.elf",
                      "ELF",
                      "ram:00100000",
                      "ram:00100000",
                      "ram:00100fff",
                      "x86:LE:64:default",
                      "gcc",
                      Instant.EPOCH,
                      Instant.EPOCH,
                      1L,
                      1L);
                }
                case "saveProgram" -> {
                  observedOrder.add("program.save");
                  yield null;
                }
                default -> throw new AssertionError("Unexpected ProgramService call: " + name);
              };
            });

    MemoryService memoryService =
        proxy(
            MemoryService.class,
            (name, args) -> {
              if (probeMode.get()) {
                return probeHandler.invoke(name, args);
              }
              recordLockedExecution.run();
              if ("readMemoryRange".equals(name)) {
                observedOrder.add("memory.read");
                return new MemoryResource(
                    "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, "90909090", 4));
              }
              throw new AssertionError("Unexpected MemoryService call: " + name);
            });

    SymbolService symbolService =
        proxy(
            SymbolService.class,
            (name, args) -> {
              if (probeMode.get()) {
                return probeHandler.invoke(name, args);
              }
              recordLockedExecution.run();
              if ("demangleSymbols".equals(name)) {
                observedOrder.add("symbol.demangle");
                return new SymbolService.DemangleResult(1, 0, List.of());
              }
              throw new AssertionError("Unexpected SymbolService call: " + name);
            });

    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (name, args) -> {
              if ("close".equals(name)) return null;
              if ("getStatus".equals(name)) {
                if (dispatcherRef.get().isSequenceLockedByCurrentThread()
                    && !observedOrder.contains("batch.analysis")) {
                  recordLockedExecution.run();
                  observedOrder.add("batch.analysis");
                }
                return new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    true,
                    null,
                    null,
                    null,
                    null);
              }
              throw new AssertionError("Unexpected AnalysisService call: " + name);
            });

    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            assertTrue(dispatcherRef.get().isSequenceLockedByCurrentThread());
            try {
              return operation.execute();
            } catch (RuntimeException runtime) {
              throw runtime;
            } catch (Exception checked) {
              throw new IllegalStateException(checked);
            }
          }
        };

    return new BridgeServices(
        programService,
        proxy(AddressService.class, probeHandler),
        proxy(CommentService.class, probeHandler),
        proxy(ReferenceService.class, probeHandler),
        memoryService,
        proxy(ListingService.class, probeHandler),
        proxy(FunctionService.class, probeHandler),
        proxy(GlobalVariableService.class, probeHandler),
        analysisService,
        decompilation,
        symbolService,
        proxy(DataTypeService.class, probeHandler),
        transactionRunner,
        "sample.elf");
  }

  private static Map<String, Object> sampleReadParams(String method) {
    return switch (method) {
      case "program.get",
          "program_language.get",
          "address_space.list",
          "memory_block.list",
          "code_unit.list",
          "data_unit.list",
          "global_variable.list",
          "instruction.list",
          "function.list",
          "symbol.list",
          "comment.list",
          "data_type_category.list",
          "data_type.list" ->
          Map.of();
      case "address.resolve", "global_variable.get", "instruction.get" ->
          Map.of("selector", Map.of("address", "ram:00100000"));
      case "memory_block.get" -> Map.of("selector", Map.of("name", ".text"));
      case "memory.read" -> Map.of("selector", Map.of("address", "ram:00100000"), "length", 4);
      case "flow_override.list" ->
          Map.of(
              "filter",
              Map.of("selector", Map.of("kind", "address", "address", "ram:00100000")));
      case "function.get", "decompilation.get" ->
          Map.of("selector", Map.of("entry", "ram:00100000"));
      case "function_call.list" -> Map.of("filter", Map.of("entry", "ram:00100000"));
      case "symbol.get" -> Map.of("selector", Map.of("id", "1"));
      case "reference.list" -> Map.of("filter", Map.of("direction", "to", "to", "ram:00100000"));
      case "comment.get" -> Map.of("selector", Map.of("address", "ram:00100000", "type", "eol"));
      case "data_type.get" -> Map.of("selector", Map.of("path", "/int"));
      default -> throw new AssertionError("Unhandled read method: " + method);
    };
  }

  private static final class LockedProbeSignal extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private LockedProbeSignal(String serviceMethod) {
      super(serviceMethod);
    }
  }

  private static DecompilationResource sampleDecompilation() {
    return new DecompilationResource(
        "ram:00100000",
        "main",
        DecompilationResource.Format.TEXT,
        true,
        200L,
        "int main(void) { return 0; }\n",
        null,
        null,
        null,
        null,
        List.of());
  }

  private static Callable<Long> timedCall(CountDownLatch startGate, Callable<?> action) {
    return () -> {
      assertTrue(startGate.await(5, TimeUnit.SECONDS));
      long started = System.nanoTime();
      action.call();
      return System.nanoTime() - started;
    };
  }

  private static long medianNanos(List<Future<Long>> futures) throws Exception {
    List<Long> samples = new ArrayList<>(futures.size());
    for (Future<Long> future : futures) {
      samples.add(future.get(5, TimeUnit.SECONDS));
    }
    Collections.sort(samples);
    return samples.get(samples.size() / 2);
  }

  private static TransactionRunner unexpectedTransactions() {
    return new TransactionRunner() {
      @Override
      public <T> T run(Operation<T> operation) {
        throw new AssertionError("Unexpected transaction");
      }
    };
  }

  private static BridgeServices stubServices(String programName, AtomicInteger closeCount) {
    AnalysisService analysis = closeableStub(AnalysisService.class, closeCount);
    DecompilationService decompilation = closeableStub(DecompilationService.class, closeCount);
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        unused(CommentService.class),
        unused(ReferenceService.class),
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysis,
        decompilation,
        unused(SymbolService.class),
        unused(DataTypeService.class),
        unexpectedTransactions(),
        programName);
  }

  @FunctionalInterface
  private interface ProxyHandler {
    Object invoke(String methodName, Object[] args);
  }

  private static <T> T proxy(Class<T> type, ProxyHandler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }

  private static <T> T closeableStub(Class<T> type, AtomicInteger closeCount) {
    return proxy(
        type,
        (methodName, args) -> {
          if ("close".equals(methodName)) {
            closeCount.incrementAndGet();
            return null;
          }
          throw new AssertionError("Unexpected call: " + methodName);
        });
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (methodName, args) -> {
          throw new AssertionError("Unexpected call: " + methodName);
        });
  }
}
