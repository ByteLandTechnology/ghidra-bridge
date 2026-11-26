package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiException;
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
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.AddressOrRangeScope;
import app.byteland.ghidra.service.listing.CodeUnitClearReceipt;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
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
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AgentDispatcherConcurrencyTest {

  record LockObservation(int readHoldCount, int readLockCount, boolean writeLocked) {}

  @Test
  void barrierUsesFairReadWriteLock() {
    TestHarness harness = new TestHarness();
    try (AgentDispatcher dispatcher = harness.dispatcher) {
      assertTrue(dispatcher.barrier().isFair(), "DispatchBarrier must use a fair RW lock");
    }
  }

  @Test
  void allTwentyNineReadOnlyMethodsAndReadOnlyBatchAcquireSharedReadLock() throws Exception {
    TestHarness harness = new TestHarness();
    try (AgentDispatcher dispatcher = harness.dispatcher) {
      List<String> catalogReadOnly =
          dispatcher.methodCatalog().methods().stream()
              .filter(m -> Boolean.TRUE.equals(((Map<?, ?>) m.contractValue().get("effects")).get("read_only")))
              .map(MethodDescriptor::name)
              .toList();
      assertEquals(29, catalogReadOnly.size(), "Catalog must expose all 29 read-only methods");

      Map<String, Map<String, Object>> readCalls = validReadRequests();
      assertEquals(Set.copyOf(catalogReadOnly), readCalls.keySet());

      for (Map.Entry<String, Map<String, Object>> entry : readCalls.entrySet()) {
        String method = entry.getKey();
        harness.lastObservation.set(null);
        Object response = dispatcher.dispatch(method, entry.getValue());
        assertTrue(response instanceof Map<?, ?>, "Expected map response for " + method);
        LockObservation obs =
            "interface.get".equals(method) || "session.get".equals(method)
                ? new LockObservation(1, 1, false)
                : harness.observationsByMethod.get(method);
        if (!"interface.get".equals(method) && !"session.get".equals(method)) {
          assertTrue(obs != null, "Handler must have executed for " + method);
        }
        assertEquals(1, obs.readHoldCount(), "Read lock hold count for " + method);
        assertFalse(obs.writeLocked(), "Read method must not acquire write lock: " + method);
      }

      // Verify session.get and read-only batch.execute (per_item and all_or_none) directly
      CountDownLatch slowDecompEntered = new CountDownLatch(1);
      CountDownLatch releaseSlowDecomp = new CountDownLatch(1);
      harness.decompileStarted = slowDecompEntered;
      harness.decompileRelease = releaseSlowDecomp;

      try (ExecutorService pool = Executors.newFixedThreadPool(22)) {
        Future<Object> decompFuture =
            pool.submit(
                () ->
                    dispatcher.dispatch(
                        "decompilation.get",
                        Map.of("selector", Map.of("entry", "ram:00100000"))));
        assertTrue(slowDecompEntered.await(5, TimeUnit.SECONDS));

        List<Future<Long>> fastReadNanos = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
          final int idx = i;
          fastReadNanos.add(
              pool.submit(
                  () -> {
                    long start = System.nanoTime();
                    switch (idx % 5) {
                      case 0 -> dispatcher.dispatch("program.get", Map.of());
                      case 1 ->
                          dispatcher.dispatch(
                              "memory.read",
                              Map.of("selector", Map.of("address", "ram:00100000"), "length", 16));
                      case 2 -> dispatcher.dispatch("session.get", Map.of());
                      case 3 -> dispatcher.dispatch("analysis.get", Map.of());
                      default ->
                          dispatcher.dispatch(
                              "batch.execute",
                              Map.of(
                                  "transaction_mode",
                                  idx % 2 == 0 ? "per_item" : "all_or_none",
                                  "items",
                                  List.of(
                                      Map.of(
                                          "id",
                                          "p",
                                          "method",
                                          "program.get",
                                          "arguments",
                                          Map.of()),
                                      Map.of(
                                          "id",
                                          "s",
                                          "method",
                                          "session.get",
                                          "arguments",
                                          Map.of()))));
                    }
                    return System.nanoTime() - start;
                  }));
        }

        // All 20 fast reads and read-only batches must finish while decompilation.get is still blocked!
        for (Future<Long> future : fastReadNanos) {
          long elapsedMs = TimeUnit.NANOSECONDS.toMillis(future.get(2, TimeUnit.SECONDS));
          assertTrue(elapsedMs < 500, "Fast read blocked behind decompilation: " + elapsedMs + "ms");
        }
        assertFalse(decompFuture.isDone(), "Slow decompilation should still be holding read lock");
        assertTrue(
            harness.maxObservedReadLockCount.get() >= 2,
            "Concurrent reads must overlap under shared read lock");

        releaseSlowDecomp.countDown();
        decompFuture.get(5, TimeUnit.SECONDS);
      }
    }
  }

  @Test
  void allTwentySixMutationsMutatingBatchesAndShutdownAcquireFairWriteLock() throws Exception {
    TestHarness harness = new TestHarness();
    try (AgentDispatcher dispatcher = harness.dispatcher) {
      assertEquals(59, dispatcher.methodCatalog().methods().size());

      List<Map.Entry<String, Map<String, Object>>> writeCalls = validMutationRequests();
      assertEquals(28, writeCalls.size(), "All 28 single-mutation methods must be tested");

      for (Map.Entry<String, Map<String, Object>> call : writeCalls) {
        String method = call.getKey();
        harness.lastWriteMethodObservation.set(null);
        // Reset state needed for create vs patch/delete idempotency
        if ("comment.create".equals(method)) {
          harness.commentPresent.set(false);
        } else if ("comment.patch".equals(method) || "comment.delete".equals(method)) {
          harness.commentPresent.set(true);
        }
        if ("data_type.create".equals(method)) {
          harness.dataTypeExistsForCreateCheck.set(false);
        } else {
          harness.dataTypeExistsForCreateCheck.set(true);
        }

        Object response = dispatcher.dispatch(method, call.getValue());
        assertTrue(response instanceof Map<?, ?>, "Expected map response for " + method);
        LockObservation obs = harness.lastWriteMethodObservation.get();
        assertTrue(obs != null, "Expected write observation for " + method);
        assertTrue(obs.writeLocked(), "Mutation must hold write lock: " + method);
        assertEquals(0, obs.readHoldCount(), "Mutation must not hold read lock: " + method);
      }

      // Mutating batch (per_item), mutating batch (all_or_none), and mixed read+write batch (26th method: batch.execute)
      for (String mode : List.of("per_item", "all_or_none")) {
        harness.lastWriteMethodObservation.set(null);
        dispatcher.dispatch(
            "batch.execute",
            Map.of(
                "transaction_mode",
                mode,
                "items",
                List.of(
                    Map.of("id", "r1", "method", "program.get", "arguments", Map.of()),
                    Map.of(
                        "id",
                        "w1",
                        "method",
                        "comment.upsert",
                        "arguments",
                        Map.of(
                            "resource",
                            Map.of(
                                "address", "ram:00100000",
                                "type", "eol",
                                "text", "updated-" + mode))))));
        LockObservation batchObs = harness.lastWriteMethodObservation.get();
        assertTrue(batchObs != null && batchObs.writeLocked(), "Mixed/mutating batch must hold write lock");
      }

      // Lifecycle actions via runExclusive and session.shutdown must acquire the fair write lock.
      AtomicReference<LockObservation> exclusiveObs = new AtomicReference<>();
      dispatcher.runExclusive(
          () ->
              exclusiveObs.set(
                  new LockObservation(
                      dispatcher.barrier().readHoldCount(),
                      dispatcher.barrier().readLockCount(),
                      dispatcher.barrier().isWriteLockedByCurrentThread())));
      assertTrue(exclusiveObs.get().writeLocked(), "runExclusive must hold write lock");
      assertEquals(0, exclusiveObs.get().readHoldCount());

      assertFalse(dispatcher.isShuttingDown());
      Object shutdownResp = dispatcher.dispatch("session.shutdown", Map.of());
      assertEquals(Map.of("shutdown", true), shutdownResp);
      assertTrue(dispatcher.isShuttingDown());
    }
  }

  @Test
  void strictObjectCodecProjectionAndJsonValueCodecRunOutsideDispatchLock() throws Exception {
    TestHarness harness = new TestHarness();
    try (AgentDispatcher dispatcher = harness.dispatcher;
        ExecutorService pool = Executors.newFixedThreadPool(4)) {
      CountDownLatch writerEntered = new CountDownLatch(1);
      CountDownLatch releaseWriter = new CountDownLatch(1);
      harness.writeStarted = writerEntered;
      harness.writeRelease = releaseWriter;

      Future<Object> blockedWrite =
          pool.submit(
              () ->
                  dispatcher.dispatch(
                      "comment.upsert",
                      Map.of(
                          "resource",
                          Map.of("address", "ram:00100000", "type", "eol", "text", "hold-lock"))));
      assertTrue(writerEntered.await(5, TimeUnit.SECONDS));

      // While the write lock is completely held, pre-lock codecs and projection checks must fail fast without waiting!
      Future<Void> preLockChecks =
          pool.submit(
              () -> {
                ApiException missing =
                    assertThrows(ApiException.class, () -> dispatcher.dispatch("", Map.of()));
                assertEquals("missing_method", missing.error().code());

                ApiException unknown =
                    assertThrows(
                        ApiException.class, () -> dispatcher.dispatch("unknown.op", Map.of()));
                assertEquals(404, unknown.status());

                // StrictObjectCodec check
                ApiException badSchema =
                    assertThrows(
                        ApiException.class,
                        () -> dispatcher.dispatch("program.get", Map.of("unexpected_key", 123)));
                assertEquals(400, badSchema.status());

                // FieldProjection checks (via canonical projection.fields)
                ApiException badField =
                    assertThrows(
                        ApiException.class,
                        () ->
                            dispatcher.dispatch(
                                "program.get",
                                Map.of("projection", Map.of("fields", List.of("not_a_field")))));
                assertEquals(400, badField.status());

                ApiException duplicateField =
                    assertThrows(
                        ApiException.class,
                        () ->
                            dispatcher.dispatch(
                                "program.get",
                                Map.of("projection", Map.of("fields", List.of("name", "name")))));
                assertEquals("duplicate_field", duplicateField.error().code());

                // BatchMethod pre-lock item validation + projection validation
                ApiException badBatch =
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
                                            "item1",
                                            "method",
                                            "program.get",
                                            "arguments",
                                            Map.of(
                                                "projection",
                                                Map.of("fields", List.of("name", "name"))))))));
                assertEquals(400, badBatch.status());
                assertEquals("validation_failed", badBatch.error().code());
                return null;
              });

      preLockChecks.get(500, TimeUnit.MILLISECONDS);
      assertFalse(blockedWrite.isDone(), "Writer must still be holding the write lock");

      releaseWriter.countDown();
      blockedWrite.get(5, TimeUnit.SECONDS);

      // Verify post-lock JsonValueCodec runs AFTER the read/write lock is released
      harness.returnCorruptLanguageResponse.set(true);
      ApiException invalidResponse =
          assertThrows(
              ApiException.class, () -> dispatcher.dispatch("program_language.get", Map.of()));
      assertEquals(500, invalidResponse.status());
      assertEquals("invalid_response", invalidResponse.error().code());
      assertEquals(0, dispatcher.barrier().readLockCount());
      assertFalse(dispatcher.barrier().isWriteLockedByCurrentThread());

      // Read-only all_or_none batch translates post-lock item encoding failures to 409 batch_rolled_back
      ApiException readOnlyAllOrNoneFailure =
          assertThrows(
              ApiException.class,
              () ->
                  dispatcher.dispatch(
                      "batch.execute",
                      Map.of(
                          "transaction_mode",
                          "all_or_none",
                          "items",
                          List.of(
                              Map.of("id", "ok-prog", "method", "program.get", "arguments", Map.of()),
                              Map.of(
                                  "id",
                                  "bad-lang",
                                  "method",
                                  "program_language.get",
                                  "arguments",
                                  Map.of())))));
      assertEquals(409, readOnlyAllOrNoneFailure.status());
      assertEquals("batch_rolled_back", readOnlyAllOrNoneFailure.error().code());
      assertEquals("bad-lang", readOnlyAllOrNoneFailure.error().details().get("failed_item"));
      assertEquals(0, dispatcher.barrier().readLockCount());

      // Transactional all_or_none batch rolls back prior mutations if a later item fails encodeResponse
      String beforeRollback = harness.committedComment.get();
      ApiException transactionalEncodeRollback =
          assertThrows(
              ApiException.class,
              () ->
                  dispatcher.dispatch(
                      "batch.execute",
                      Map.of(
                          "transaction_mode",
                          "all_or_none",
                          "items",
                          List.of(
                              Map.of(
                                  "id",
                                  "mut-1",
                                  "method",
                                  "comment.upsert",
                                  "arguments",
                                  Map.of(
                                      "resource",
                                      Map.of(
                                          "address", "ram:00100000",
                                          "type", "eol",
                                          "text", "ROLLBACK_ON_ENCODE_FAILURE"))),
                              Map.of(
                                  "id",
                                  "bad-lang",
                                  "method",
                                  "program_language.get",
                                  "arguments",
                                  Map.of())))));
      assertEquals(409, transactionalEncodeRollback.status());
      assertEquals("batch_rolled_back", transactionalEncodeRollback.error().code());
      assertEquals("bad-lang", transactionalEncodeRollback.error().details().get("failed_item"));
      assertEquals(beforeRollback, harness.committedComment.get());
      assertEquals(0, harness.activeTransactions.get());
      assertFalse(dispatcher.barrier().isWriteLockedByCurrentThread());
      harness.returnCorruptLanguageResponse.set(false);

      // Also verify response JsonValueCodec + FieldProjection run while write lock is held
      var registry =
          new app.byteland.ghidra.api.ApiRegistry(
              harness.services, "sess-1", () -> Map.of("id", "sess-1"), () -> {});
      var preparedRead =
          registry.prepareDispatch(
              "program.get",
              Map.of("projection", Map.of("fields", List.of("name", "language_id"))));
      Object rawResult = dispatcher.barrier().runRead(preparedRead::execute);

      CountDownLatch secondWriteEntered = new CountDownLatch(1);
      CountDownLatch secondWriteRelease = new CountDownLatch(1);
      harness.writeStarted = secondWriteEntered;
      harness.writeRelease = secondWriteRelease;
      Future<Object> secondBlockedWrite =
          pool.submit(
              () ->
                  dispatcher.dispatch(
                      "comment.upsert",
                      Map.of(
                          "resource",
                          Map.of("address", "ram:00100000", "type", "eol", "text", "hold-2"))));
      assertTrue(secondWriteEntered.await(5, TimeUnit.SECONDS));

      Map<?, ?> projected =
          pool.submit(() -> (Map<?, ?>) preparedRead.encodeResponse(rawResult))
              .get(500, TimeUnit.MILLISECONDS);
      assertEquals(Map.of("name", "test-program", "language_id", "x86:LE:64:default"), projected);
      assertFalse(secondBlockedWrite.isDone());

      secondWriteRelease.countDown();
      secondBlockedWrite.get(5, TimeUnit.SECONDS);
    }
  }

  @Test
  void concurrentReadWriteAndBatchStressPreventsStarvationLeaksAndDirtyReads() throws Exception {
    TestHarness harness = new TestHarness();
    try (AgentDispatcher dispatcher = harness.dispatcher;
        ExecutorService pool = Executors.newFixedThreadPool(20)) {
      CountDownLatch startGate = new CountDownLatch(1);
      AtomicBoolean stopReaders = new AtomicBoolean(false);
      AtomicReference<Throwable> failure = new AtomicReference<>();

      List<Future<?>> readers = new ArrayList<>();
      for (int r = 0; r < 14; r++) {
        final int readerId = r;
        readers.add(
            pool.submit(
                () -> {
                  try {
                    startGate.await();
                    while (!stopReaders.get()) {
                      Map<?, ?> comment =
                          (Map<?, ?>)
                              dispatcher.dispatch(
                                  "comment.get",
                                  Map.of(
                                      "selector",
                                      Map.of("address", "ram:00100000", "type", "eol")));
                      String text = String.valueOf(comment.get("text"));
                      assertFalse(
                          text.startsWith("UNCOMMITTED") || text.startsWith("ROLLBACK"),
                          "Reader saw uncommitted or rolled-back data: " + text);
                      if (readerId % 3 == 0) {
                        dispatcher.dispatch(
                            "batch.execute",
                            Map.of(
                                "items",
                                List.of(
                                    Map.of(
                                        "id",
                                        "c",
                                        "method",
                                        "comment.get",
                                        "arguments",
                                        Map.of(
                                            "selector",
                                            Map.of("address", "ram:00100000", "type", "eol"))),
                                    Map.of(
                                        "id", "p", "method", "program.get", "arguments", Map.of()))));
                      }
                    }
                  } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                  }
                }));
      }

      List<Future<Long>> writers = new ArrayList<>();
      for (int w = 0; w < 4; w++) {
        final int writerId = w;
        writers.add(
            pool.submit(
                () -> {
                  startGate.await();
                  long maxWaitNanos = 0L;
                  for (int iter = 0; iter < 25; iter++) {
                    long t0 = System.nanoTime();
                    int mode = (writerId + iter) % 3;
                    if (mode == 0) {
                      String committedVal = "COMMITTED_SINGLE_" + writerId + "_" + iter;
                      dispatcher.dispatch(
                          "comment.upsert",
                          Map.of(
                              "resource",
                              Map.of(
                                  "address", "ram:00100000",
                                  "type", "eol",
                                  "text", committedVal)));
                    } else if (mode == 1) {
                      String committedVal = "COMMITTED_BATCH_" + writerId + "_" + iter;
                      dispatcher.dispatch(
                          "batch.execute",
                          Map.of(
                              "transaction_mode",
                              "all_or_none",
                              "items",
                              List.of(
                                  Map.of(
                                      "id",
                                      "u1",
                                      "method",
                                      "comment.upsert",
                                      "arguments",
                                      Map.of(
                                          "resource",
                                          Map.of(
                                              "address", "ram:00100000",
                                              "type", "eol",
                                              "text", committedVal))))));
                    } else {
                      // Failing all_or_none batch: first item mutates to ROLLBACK_*, second item fails -> must roll back!
                      final int iteration = iter;
                      ApiException rolledBack =
                          assertThrows(
                              ApiException.class,
                              () ->
                                  dispatcher.dispatch(
                                      "batch.execute",
                                      Map.of(
                                          "transaction_mode",
                                          "all_or_none",
                                          "items",
                                          List.of(
                                              Map.of(
                                                  "id",
                                                  "dirty",
                                                  "method",
                                                  "comment.upsert",
                                                  "arguments",
                                                  Map.of(
                                                      "resource",
                                                      Map.of(
                                                          "address", "ram:00100000",
                                                          "type", "eol",
                                                          "text", "ROLLBACK_" + writerId + "_" + iteration))),
                                              Map.of(
                                                  "id",
                                                  "boom",
                                                  "method",
                                                  "comment.upsert",
                                                  "arguments",
                                                  Map.of(
                                                      "resource",
                                                      Map.of(
                                                          "address", "ram:00100000",
                                                          "type", "eol",
                                                          "text", "TRIGGER_FAILURE")))))));
                      assertEquals(409, rolledBack.status());
                      assertEquals("batch_rolled_back", rolledBack.error().code());
                    }
                    maxWaitNanos = Math.max(maxWaitNanos, System.nanoTime() - t0);
                  }
                  return maxWaitNanos;
                }));
      }

      startGate.countDown();
      for (Future<Long> writer : writers) {
        long maxWaitMs = TimeUnit.NANOSECONDS.toMillis(writer.get(15, TimeUnit.SECONDS));
        assertTrue(maxWaitMs < 5_000, "Fair write lock must prevent writer starvation: " + maxWaitMs);
      }
      stopReaders.set(true);
      for (Future<?> reader : readers) {
        reader.get(5, TimeUnit.SECONDS);
      }

      if (failure.get() != null) {
        throw new AssertionError("Concurrent stress failure", failure.get());
      }
      assertEquals(0, harness.activeTransactions.get(), "Zero transaction leaks allowed");
      assertFalse(harness.overlapViolation.get(), "Readers and writers must never overlap");
    }
  }

  @Test
  void analysisRunningRejectsWritesWith409WhileReadsRunConcurrentlyAndCloseDrainsInFlight()
      throws Exception {
    TestHarness harness = new TestHarness();
    AgentDispatcher dispatcher = harness.dispatcher;
    harness.analysisRunning.set(true);

    // Reads and read-only batches succeed during analysis
    assertEquals("test-program", ((Map<?, ?>) dispatcher.dispatch("program.get", Map.of())).get("name"));
    dispatcher.dispatch(
        "batch.execute",
        Map.of("items", List.of(Map.of("id", "1", "method", "analysis.get", "arguments", Map.of()))));

    // analysis.start returns 409 analysis_already_running
    ApiException alreadyRunning =
        assertThrows(ApiException.class, () -> dispatcher.dispatch("analysis.start", Map.of()));
    assertEquals(409, alreadyRunning.status());
    assertEquals("analysis_already_running", alreadyRunning.error().code());

    // Mutations and mutating batches return 409 analysis_in_progress
    ApiException inProgress =
        assertThrows(ApiException.class, () -> dispatcher.dispatch("program.save", Map.of()));
    assertEquals(409, inProgress.status());
    assertEquals("analysis_in_progress", inProgress.error().code());

    ApiException batchInProgress =
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
                                "1",
                                "method",
                                "comment.upsert",
                                "arguments",
                                Map.of(
                                    "resource",
                                    Map.of(
                                        "address", "ram:00100000",
                                        "type", "eol",
                                        "text", "denied")))))));
    assertEquals(409, batchInProgress.status());
    assertEquals("analysis_in_progress", batchInProgress.error().code());

    harness.analysisRunning.set(false);

    // Verify close() waits for active read dispatch before closing services and rejects new calls
    CountDownLatch inFlightStarted = new CountDownLatch(1);
    CountDownLatch releaseInFlight = new CountDownLatch(1);
    harness.decompileStarted = inFlightStarted;
    harness.decompileRelease = releaseInFlight;

    try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
      Future<Object> activeRead =
          pool.submit(
              () ->
                  dispatcher.dispatch(
                      "decompilation.get", Map.of("selector", Map.of("entry", "ram:00100000"))));
      assertTrue(inFlightStarted.await(5, TimeUnit.SECONDS));

      Future<?> closeFuture = pool.submit(dispatcher::close);
      Thread.sleep(40L);
      assertFalse(harness.servicesClosed.get(), "Services must not close while dispatch is active");
      assertThrows(
          IllegalStateException.class, () -> dispatcher.dispatch("program.get", Map.of()));

      releaseInFlight.countDown();
      activeRead.get(5, TimeUnit.SECONDS);
      closeFuture.get(5, TimeUnit.SECONDS);
      assertTrue(harness.servicesClosed.get(), "Services must close once in-flight dispatch drains");
    }
  }

  private static Map<String, Map<String, Object>> validReadRequests() {
    Map<String, Map<String, Object>> calls = new LinkedHashMap<>();
    calls.put("interface.get", Map.of());
    calls.put("session.get", Map.of());
    calls.put("program.get", Map.of());
    calls.put("program_language.get", Map.of());
    calls.put("address_space.list", Map.of());
    calls.put("address.resolve", Map.of("selector", Map.of("address", "ram:00100000")));
    calls.put("memory_block.get", Map.of("selector", Map.of("name", ".text")));
    calls.put("memory_block.list", Map.of());
    calls.put("memory.read", Map.of("selector", Map.of("address", "ram:00100000"), "length", 4));
    calls.put("code_unit.list", Map.of());
    calls.put("data_unit.list", Map.of());
    calls.put("instruction.get", Map.of("selector", Map.of("address", "ram:00100000")));
    calls.put("instruction.list", Map.of());
    calls.put(
        "flow_override.list",
        Map.of("filter", Map.of("selector", Map.of("kind", "address", "address", "ram:00100000"))));
    calls.put("global_variable.get", Map.of("selector", Map.of("address", "ram:00100100")));
    calls.put("global_variable.list", Map.of());
    calls.put("function.get", Map.of("selector", Map.of("entry", "ram:00100000")));
    calls.put("function.list", Map.of());
    calls.put("function_call.list", Map.of("filter", Map.of("entry", "ram:00100000")));
    calls.put("analysis.get", Map.of());
    calls.put("decompilation.get", Map.of("selector", Map.of("entry", "ram:00100000")));
    calls.put("symbol.get", Map.of("selector", Map.of("id", "1")));
    calls.put("symbol.list", Map.of());
    calls.put(
        "reference.list",
        Map.of("filter", Map.of("direction", "to", "to", "ram:00100000")));
    calls.put(
        "comment.get",
        Map.of("selector", Map.of("address", "ram:00100000", "type", "eol")));
    calls.put("comment.list", Map.of());
    calls.put("data_type_category.list", Map.of());
    calls.put("data_type.get", Map.of("selector", Map.of("path", "/DemoStruct")));
    calls.put("data_type.list", Map.of());
    return calls;
  }

  private static List<Map.Entry<String, Map<String, Object>>> validMutationRequests() {
    Map<String, Object> intRef = Map.of("kind", "named", "name", "int");
    List<Map.Entry<String, Map<String, Object>>> calls = new ArrayList<>();
    calls.add(Map.entry("program.save", Map.of()));
    calls.add(
        Map.entry(
            "memory.write",
            Map.of(
                "selector", Map.of("address", "ram:00100000"),
                "patch",
                    Map.of(
                        "bytes", Map.of("encoding", "hex", "data", "9090", "length", 2)))));
    calls.add(
        Map.entry(
            "code_unit.clear",
            Map.of("selector", Map.of("kind", "address", "address", "ram:00100000"))));
    calls.add(
        Map.entry(
            "instruction.assemble",
            Map.of(
                "selector", Map.of("address", "ram:00100000"),
                "instructions", List.of("NOP"))));
    calls.add(
        Map.entry(
            "instruction.disassemble",
            Map.of("selector", Map.of("kind", "address", "address", "ram:00100000"))));
    calls.add(
        Map.entry(
            "flow_override.patch",
            Map.of(
                "selector", Map.of("kind", "address", "address", "ram:00100000"),
                "patch", Map.of("flow_override", "call_return"))));
    calls.add(
        Map.entry(
            "global_variable.create",
            Map.of(
                "resource",
                Map.of("address", "ram:00100100", "name", "g_var", "data_type", intRef))));
    calls.add(
        Map.entry(
            "global_variable.patch",
            Map.of(
                "selector", Map.of("address", "ram:00100100"),
                "patch", Map.of("name", "g_var_renamed"))));
    calls.add(
        Map.entry(
            "global_variable.upsert",
            Map.of(
                "resource",
                Map.of("address", "ram:00100100", "name", "g_var", "data_type", intRef))));
    calls.add(
        Map.entry(
            "global_variable.delete",
            Map.of("selector", Map.of("address", "ram:00100100"))));
    calls.add(
        Map.entry(
            "function.create",
            Map.of("resource", Map.of("entry", "ram:00100000", "name", "fn_main"))));
    calls.add(
        Map.entry(
            "function.patch",
            Map.of(
                "selector", Map.of("entry", "ram:00100000"),
                "patch", Map.of("name", "fn_patched"))));
    calls.add(
        Map.entry("function.delete", Map.of("selector", Map.of("entry", "ram:00100000"))));
    calls.add(
        Map.entry(
            "function_parameter.create",
            Map.of(
                "selector", Map.of("entry", "ram:00100000"),
                "resource",
                    Map.of("ordinal", 0, "name", "arg0", "data_type", intRef))));
    calls.add(
        Map.entry(
            "function_parameter.patch",
            Map.of(
                "selector", Map.of("entry", "ram:00100000", "ordinal", 0),
                "patch", Map.of("name", "arg0"))));
    calls.add(
        Map.entry(
            "function_parameter.delete",
            Map.of("selector", Map.of("entry", "ram:00100000", "ordinal", 0))));
    calls.add(
        Map.entry(
            "function_local_variable.patch",
            Map.of(
                "selector", Map.of("entry", "ram:00100000", "name", "local_0"),
                "patch", Map.of("name", "local_0"))));
    calls.add(Map.entry("analysis.start", Map.of()));
    calls.add(Map.entry("symbol.demangle", Map.of()));
    calls.add(
        Map.entry(
            "symbol.patch",
            Map.of(
                "selector", Map.of("id", "1"),
                "patch", Map.of("name", "sym_renamed"))));
    calls.add(
        Map.entry(
            "comment.create",
            Map.of(
                "resource",
                Map.of("address", "ram:00100000", "type", "eol", "text", "created"))));
    calls.add(
        Map.entry(
            "comment.patch",
            Map.of(
                "selector", Map.of("address", "ram:00100000", "type", "eol"),
                "patch", Map.of("text", "patched"))));
    calls.add(
        Map.entry(
            "comment.upsert",
            Map.of(
                "resource",
                Map.of("address", "ram:00100000", "type", "eol", "text", "upserted"))));
    calls.add(
        Map.entry(
            "comment.delete",
            Map.of("selector", Map.of("address", "ram:00100000", "type", "eol"))));
    calls.add(
        Map.entry(
            "data_type.create",
            Map.of("resource", Map.of("kind", "struct", "name", "DemoStruct", "size", 4))));
    calls.add(
        Map.entry(
            "data_type.patch",
            Map.of(
                "selector", Map.of("path", "/DemoStruct"),
                "patch", Map.of("kind", "struct"))));
    calls.add(
        Map.entry(
            "data_type.upsert",
            Map.of(
                "resource",
                Map.of(
                    "kind",
                    "function",
                    "name",
                    "DemoFnType",
                    "signature",
                    Map.of(
                        "return_type", intRef,
                        "parameters", List.of(),
                        "calling_convention", "__stdcall",
                        "has_var_args", false,
                        "has_no_return", false)))));
    calls.add(
        Map.entry("data_type.delete", Map.of("selector", Map.of("path", "/DemoStruct"))));
    return calls;
  }

  private static final class TestHarness {
    final AtomicBoolean analysisRunning = new AtomicBoolean(false);
    final AtomicBoolean servicesClosed = new AtomicBoolean(false);
    final AtomicBoolean commentPresent = new AtomicBoolean(true);
    final AtomicBoolean dataTypeExistsForCreateCheck = new AtomicBoolean(true);
    final AtomicBoolean returnCorruptLanguageResponse = new AtomicBoolean(false);
    final AtomicBoolean overlapViolation = new AtomicBoolean(false);
    final AtomicInteger activeReaders = new AtomicInteger();
    final AtomicInteger activeWriters = new AtomicInteger();
    final AtomicInteger activeTransactions = new AtomicInteger();
    final AtomicInteger maxObservedReadLockCount = new AtomicInteger();
    final AtomicLong revision = new AtomicLong(1);
    final AtomicReference<String> committedComment = new AtomicReference<>("COMMITTED_INIT");
    final AtomicReference<String> stagedComment = new AtomicReference<>(null);
    final AtomicReference<LockObservation> lastObservation = new AtomicReference<>();
    final AtomicReference<LockObservation> lastWriteMethodObservation = new AtomicReference<>();
    final Map<String, LockObservation> observationsByMethod = new ConcurrentHashMap<>();

    volatile CountDownLatch decompileStarted;
    volatile CountDownLatch decompileRelease;
    volatile CountDownLatch writeStarted;
    volatile CountDownLatch writeRelease;

    final BridgeServices services;
    final AgentDispatcher dispatcher;

    TestHarness() {
      this.services =
          new BridgeServices(
              programService(),
              addressService(),
              commentService(),
              referenceService(),
              memoryService(),
              listingService(),
              functionService(),
              globalVariableService(),
              analysisService(),
              decompilationService(),
              symbolService(),
              dataTypeService(),
              transactionRunner(),
              "test-program");
      AgentConfig config =
          new AgentConfig("ws://127.0.0.1:9999/ws/agent", null, null, null, null, "sess-1", null);
      this.dispatcher = new AgentDispatcher(services, config);
    }

    private LockObservation observe(String methodName, boolean writeExpected) {
      DispatchBarrier barrier = dispatcher.barrier();
      LockObservation obs =
          new LockObservation(
              barrier.readHoldCount(),
              barrier.readLockCount(),
              barrier.isWriteLockedByCurrentThread());
      lastObservation.set(obs);
      if (methodName != null) {
        observationsByMethod.put(methodName, obs);
      }
      maxObservedReadLockCount.accumulateAndGet(obs.readLockCount(), Math::max);
      if (writeExpected) {
        lastWriteMethodObservation.set(obs);
        int writers = activeWriters.incrementAndGet();
        if (writers > 1 || activeReaders.get() > 0 || !obs.writeLocked()) {
          overlapViolation.set(true);
        }
        activeWriters.decrementAndGet();
      } else if (!obs.writeLocked()) {
        int readers = activeReaders.incrementAndGet();
        if (activeWriters.get() > 0 || readers < 1 || obs.readHoldCount() < 1) {
          overlapViolation.set(true);
        }
        activeReaders.decrementAndGet();
      }
      return obs;
    }

    private static ScanProgress completedScan() {
      return new ScanProgress(
          ScanProgress.Kind.ADDRESS,
          "ram:00100000",
          "ram:00100100",
          "ram:00100000",
          "ram:00100100",
          true,
          ScanProgress.StopReason.COMPLETED,
          1L);
    }

    private TransactionRunner transactionRunner() {
      return new TransactionRunner() {
        @Override
        public <T> T run(Operation<T> operation) {
          int depth = activeTransactions.incrementAndGet();
          if (depth == 1) {
            stagedComment.set("UNCOMMITTED_" + revision.incrementAndGet());
          }
          boolean committed = false;
          try {
            T result = operation.execute();
            committed = true;
            if (depth == 1 && stagedComment.get() != null) {
              committedComment.set(stagedComment.get());
            }
            return result;
          } catch (RuntimeException ex) {
            throw ex;
          } catch (Exception ex) {
            throw new RuntimeException(ex);
          } finally {
            if (depth == 1) {
              if (!committed) {
                stagedComment.set(null);
              } else {
                stagedComment.set(null);
              }
            }
            activeTransactions.decrementAndGet();
          }
        }
      };
    }

    private ProgramService programService() {
      return new ProgramService() {
        @Override
        public ProgramResource getProgram() {
          observe("program.get", false);
          return new ProgramResource(
              "test-program",
              "/bin/test",
              "ELF",
              "ram:00100000",
              "ram:00100000",
              "ram:0010ffff",
              "x86:LE:64:default",
              "gcc",
              Instant.EPOCH,
              Instant.EPOCH,
              1L,
              1L);
        }

        @Override
        public Page<AddressSpaceResource> getAddressSpaces(int limit, String cursor) {
          observe("address_space.list", false);
          return Page.of(
              List.of(
                  new AddressSpaceResource(
                      "ram",
                      AddressSpaceResource.Kind.RAM,
                      64,
                      "ram:00000000",
                      "ram:ffffffff",
                      true)),
              limit,
              null);
        }

        @Override
        public ProgramLanguageResource getLanguageInfo() {
          observe("program_language.get", false);
          if (returnCorruptLanguageResponse.get()) {
            return new ProgramLanguageResource(
                "x86:LE:64:default", "gcc", "x86", ProgramLanguageResource.Endian.LITTLE, -1);
          }
          return new ProgramLanguageResource(
              "x86:LE:64:default", "gcc", "x86", ProgramLanguageResource.Endian.LITTLE, 64);
        }

        @Override
        public void saveProgram() {
          observe("program.save", true);
        }
      };
    }

    private AddressService addressService() {
      return rawAddress -> {
        observe("address.resolve", dispatcher.barrier().isWriteLockedByCurrentThread());
        return new AddressResource(
            "ram:00100000", true, true, null, null, null, null);
      };
    }

    private CommentService commentService() {
      return new CommentService() {
        @Override
        public Page<CommentResource> listComments(CommentQuery query) {
          boolean writeHeld = dispatcher.barrier().isWriteLockedByCurrentThread();
          observe("comment.get", false);
          observe("comment.list", false);
          if (!commentPresent.get()) {
            return Page.scanned(List.of(), query.limit(), null, completedScan());
          }
          String visibleText =
              writeHeld && stagedComment.get() != null
                  ? stagedComment.get()
                  : committedComment.get();
          return Page.scanned(
              List.of(new CommentResource("ram:00100000", CommentResource.Type.EOL, visibleText)),
              query.limit(),
              null,
              completedScan());
        }

        @Override
        public void setComment(String addressRaw, CommentResource.Type type, String text) {
          observe("comment.write", true);
          CountDownLatch started = writeStarted;
          CountDownLatch release = writeRelease;
          if (started != null && release != null) {
            writeStarted = null;
            writeRelease = null;
            started.countDown();
            try {
              release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ex) {
              Thread.currentThread().interrupt();
            }
          }
          if ("TRIGGER_FAILURE".equals(text)) {
            throw new IllegalArgumentException("simulated mutation failure");
          }
          commentPresent.set(true);
          stagedComment.set(text);
        }

        @Override
        public void deleteComment(String addressRaw, CommentResource.Type type) {
          observe("comment.delete", true);
          commentPresent.set(false);
        }
      };
    }

    private ReferenceService referenceService() {
      return (fromRaw, toRaw, type, direction, limit, cursor) -> {
        observe("reference.list", false);
        return Page.of(
            List.of(
                new ReferenceResource(
                    "ram:00100010", "ram:00100000", "UNCONDITIONAL_CALL", 0, true, "DEFAULT")),
            limit,
            null);
      };
    }

    private MemoryService memoryService() {
      return new MemoryService() {
        @Override
        public Page<MemoryBlockResource> listMemoryBlocks(MemoryBlockQuery query) {
          observe("memory_block.list", false);
          return Page.of(List.of(sampleBlock()), query.limit(), null);
        }

        @Override
        public MemoryBlockResource getMemoryBlockByName(String rawName) {
          observe("memory_block.get", false);
          return sampleBlock();
        }

        @Override
        public MemoryResource readMemoryRange(
            String startRaw, int length, ByteSequence.Encoding encoding) {
          observe("memory.read", false);
          return new MemoryResource(
              "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, "90909090", 4));
        }

        @Override
        public void patchMemory(
            String startRaw, ByteSequence bytes, boolean clearExisting, boolean disassemble) {
          observe("memory.write", true);
        }

        private MemoryBlockResource sampleBlock() {
          return new MemoryBlockResource(
              ".text",
              "ram:00100000",
              "ram:00100fff",
              4096L,
              true,
              false,
              true,
              true,
              false,
              false,
              MemoryBlockResource.Kind.DEFAULT,
              null);
        }
      };
    }

    private ListingService listingService() {
      InstructionResource insn =
          new InstructionResource(
              "ram:00100000",
              1,
              new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
              "NOP",
              List.of(),
              FlowOverrideValue.NONE,
              "FALL_THROUGH",
              "FALL_THROUGH",
              "ram:00100001");
      return new ListingService() {
        @Override
        public Page<CodeUnitResource> listCodeUnits(
            AddressScanOptions scan, int limit, String kind, String cursor) {
          observe("code_unit.list", false);
          return Page.scanned(
              List.of(
                  new CodeUnitResource(
                      "ram:00100000",
                      CodeUnitResource.Kind.INSTRUCTION,
                      1,
                      new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                      "NOP",
                      "NOP",
                      List.of(),
                      null)),
              limit,
              null,
              completedScan());
        }

        @Override
        public Page<InstructionResource> listInstructions(
            AddressScanOptions scan, int limit, String cursor) {
          observe("instruction.list", false);
          return Page.scanned(List.of(insn), limit, null, completedScan());
        }

        @Override
        public InstructionResource getInstruction(String rawAddress) {
          observe("instruction.get", false);
          return insn;
        }

        @Override
        public List<InstructionResource> assembleInstructions(
            String rawAddress, List<String> instructions, boolean padNop) {
          observe("instruction.assemble", true);
          return List.of(insn);
        }

        @Override
        public List<InstructionResource> disassembleInstructions(
            AddressOrRangeScope scope, boolean followFlow) {
          observe("instruction.disassemble", true);
          return List.of(insn);
        }

        @Override
        public CodeUnitClearReceipt clearCodeUnits(
            AddressOrRangeScope scope, boolean clearContext) {
          observe("code_unit.clear", true);
          return new CodeUnitClearReceipt("ram:00100000", "ram:00100000", true);
        }

        @Override
        public Page<DataUnitResource> listDataUnits(
            AddressScanOptions scan, int limit, String cursor) {
          observe("data_unit.list", false);
          return Page.scanned(
              List.of(
                  new DataUnitResource(
                      "ram:00100100",
                      4,
                      DataTypeReference.named("int"),
                      "0",
                      "0h",
                      new ByteSequence(ByteSequence.Encoding.HEX, "00000000", 4))),
              limit,
              null,
              completedScan());
        }

        @Override
        public Page<InstructionResource> getFlowOverrides(
            FlowOverrideScope scope,
            List<FlowOverrideValue> flowOverrides,
            AddressScanOptions scan,
            int limit,
            String cursor) {
          observe("flow_override.list", dispatcher.barrier().isWriteLockedByCurrentThread());
          return Page.scanned(List.of(insn), limit, null, completedScan());
        }

        @Override
        public void setFlowOverrides(
            FlowOverrideScope scope,
            List<FlowOverrideValue> expectedFlowOverrides,
            FlowOverrideValue flowOverride) {
          observe("flow_override.patch", true);
        }
      };
    }

    private FunctionService functionService() {
      FunctionResource fn =
          new FunctionResource(
              "ram:00100000",
              "fn_main",
              "Global",
              new FunctionResource.Body("ram:00100000", "ram:00100010", 17L),
              "int fn_main(int arg0)",
              DataTypeReference.named("int"),
              VariableStorageReference.register("EAX"),
              1,
              "__stdcall",
              List.of(
                  new FunctionResource.ParameterResource(
                      0,
                      "arg0",
                      DataTypeReference.named("int"),
                      VariableStorageReference.register("EDI"))),
              List.of(
                  new FunctionResource.LocalVariableResource(
                      "local_0",
                      DataTypeReference.named("int"),
                      VariableStorageReference.register("EBX"))),
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
      return new FunctionService() {
        @Override
        public Page<FunctionResource> listFunctions(FunctionQuery query) {
          observe("function.list", false);
          return Page.scanned(List.of(fn), query.limit(), null, completedScan());
        }

        @Override
        public FunctionResource getFunction(String rawAddress, Set<String> includes) {
          observe("function.get", dispatcher.barrier().isWriteLockedByCurrentThread());
          return fn;
        }

        @Override
        public FunctionResource createFunction(
            String rawAddress, String name, boolean disassemble) {
          observe("function.create", true);
          return fn;
        }

        @Override
        public void deleteFunction(String rawAddress) {
          observe("function.delete", true);
        }

        @Override
        public void patchFunction(
            String rawAddress,
            String newName,
            String newComment,
            boolean commentPresent,
            DataTypeReference returnType,
            VariableStorageReference returnStorage,
            String callingConvention,
            FunctionAttributePatch attributes) {
          observe("function.patch", true);
        }

        @Override
        public Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
          observe("function_call.list", false);
          return Page.of(List.of(), limit, null);
        }

        @Override
        public Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
          observe("function_call.list", false);
          return Page.of(
              List.of(
                  new FunctionCallResource(
                      "ram:00100020",
                      "helper",
                      "ram:00100004",
                      FunctionCallResource.Direction.CALLEES,
                      "Global",
                      null)),
              limit,
              null);
        }

        @Override
        public void patchParameter(
            String rawAddress,
            int ordinal,
            String newName,
            DataTypeReference newDataType,
            VariableStorageReference storage) {
          observe("function_parameter.patch", true);
        }

        @Override
        public void addParameter(
            String rawAddress,
            int ordinal,
            String parameterName,
            DataTypeReference dataType,
            VariableStorageReference storage) {
          observe("function_parameter.create", true);
        }

        @Override
        public void removeParameter(String rawAddress, int ordinal) {
          observe("function_parameter.delete", true);
        }

        @Override
        public void patchLocalVariable(
            String rawAddress,
            String variableName,
            String newName,
            DataTypeReference newDataType) {
          observe("function_local_variable.patch", true);
        }
      };
    }

    private GlobalVariableService globalVariableService() {
      GlobalVariableResource gv =
          new GlobalVariableResource(
              "ram:00100100",
              "g_var",
              "Global",
              DataTypeReference.named("int"),
              4,
              "0",
              "0h",
              "USER_DEFINED");
      return new GlobalVariableService() {
        @Override
        public GlobalVariableResource getGlobalVariable(String address) {
          observe("global_variable.get", dispatcher.barrier().isWriteLockedByCurrentThread());
          return gv;
        }

        @Override
        public Page<GlobalVariableResource> listGlobalVariables(Query query) {
          observe("global_variable.list", false);
          return Page.scanned(List.of(gv), query.limit(), null, completedScan());
        }

        @Override
        public void writeGlobalVariable(Mutation mutation, WriteMode mode) {
          observe("global_variable.write", true);
        }

        @Override
        public void deleteGlobalVariable(String address, boolean deleteSymbol) {
          observe("global_variable.delete", true);
        }
      };
    }

    private AnalysisService analysisService() {
      return new AnalysisService() {
        @Override
        public AnalysisResource startAnalysis(List<String> analyzers) {
          observe("analysis.start", true);
          return new AnalysisResource(
              AnalysisResource.Kind.BRIDGE,
              AnalysisResource.Status.RUNNING,
              false,
              "task-1",
              Instant.EPOCH,
              null,
              0.0);
        }

        @Override
        public AnalysisResource getStatus() {
          if (!dispatcher.barrier().isWriteLockedByCurrentThread()) {
            observe("analysis.get", false);
          }
          return new AnalysisResource(
              AnalysisResource.Kind.GHIDRA,
              analysisRunning.get()
                  ? AnalysisResource.Status.RUNNING
                  : AnalysisResource.Status.IDLE,
              true,
              null,
              null,
              null,
              null);
        }

        @Override
        public void close() {
          servicesClosed.set(true);
        }
      };
    }

    private DecompilationService decompilationService() {
      return new DecompilationService() {
        @Override
        public DecompilationResource decompileFunction(
            String rawAddress,
            DecompilationResource.Format format,
            Integer timeoutMs,
            boolean includeComments) {
          observe("decompilation.get", false);
          CountDownLatch started = decompileStarted;
          CountDownLatch release = decompileRelease;
          if (started != null && release != null) {
            decompileStarted = null;
            decompileRelease = null;
            started.countDown();
            try {
              release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ex) {
              Thread.currentThread().interrupt();
            }
          }
          return new DecompilationResource(
              "ram:00100000",
              "fn_main",
              DecompilationResource.Format.TEXT,
              true,
              5L,
              "int fn_main(void) { return 0; }",
              null,
              null,
              null,
              null,
              List.of());
        }

        @Override
        public void close() {
          servicesClosed.set(true);
        }
      };
    }

    private SymbolService symbolService() {
      SymbolResource sym =
          new SymbolResource(
              "1", "fn_main", "ram:00100000", "Global", "Function", "USER_DEFINED", true, null);
      return new SymbolService() {
        @Override
        public Page<SymbolResource> listSymbols(SymbolQuery query) {
          observe("symbol.list", false);
          return Page.scanned(List.of(sym), query.limit(), null, completedScan());
        }

        @Override
        public SymbolResource getSymbol(long symbolId) {
          observe("symbol.get", dispatcher.barrier().isWriteLockedByCurrentThread());
          return sym;
        }

        @Override
        public void renameSymbol(long symbolId, String newName) {
          observe("symbol.patch", true);
        }

        @Override
        public DemangleResult demangleSymbols() {
          observe("symbol.demangle", true);
          return new DemangleResult(1, 0, List.of());
        }
      };
    }

    private DataTypeService dataTypeService() {
      DataTypeResource dt =
          new DataTypeResource(
              "/DemoStruct",
              "DemoStruct",
              "/",
              DataTypeResource.Kind.STRUCT,
              4,
              "",
              4,
              List.of(),
              null,
              null,
              null);
      return new DataTypeService() {
        @Override
        public Page<DataTypeCategoryResource> listCategories(
            String categoryPath, int limit, String cursor) {
          observe("data_type_category.list", false);
          return Page.of(
              List.of(new DataTypeCategoryResource("/", "", 0, 1)), limit, null);
        }

        @Override
        public DataTypeResource getDataType(String path) {
          boolean writeHeld = dispatcher.barrier().isWriteLockedByCurrentThread();
          observe("data_type.get", writeHeld);
          if (writeHeld && !dataTypeExistsForCreateCheck.getAndSet(true)) {
            throw new NoSuchElementException("not created yet");
          }
          return dt;
        }

        @Override
        public Page<DataTypeResource> searchDataTypes(
            String query, String categoryPath, String kind, int limit, String cursor) {
          observe("data_type.list", false);
          return Page.of(List.of(dt), limit, null);
        }

        @Override
        public void createDataType(
            String categoryPath,
            DataTypeResource.Kind kind,
            String name,
            DataTypeReference baseType,
            int size,
            FunctionSignature signature) {
          observe("data_type.create", true);
        }

        @Override
        public void patchDataType(String path, DataTypePatch patch) {
          observe("data_type.patch", true);
        }

        @Override
        public boolean deleteDataType(String path) {
          observe("data_type.delete", true);
          return true;
        }
      };
    }
  }
}
