package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Program;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class GhidraSessionAdversarialTest {

  static class TestScript extends GhidraScript {
    @Override
    protected void run() {}
  }

  static class TestCommand implements Command<Program> {
    private final boolean success;
    private final String statusMsg;

    TestCommand(boolean success, String statusMsg) {
      this.success = success;
      this.statusMsg = statusMsg;
    }

    @Override
    public boolean applyTo(Program obj) {
      return success;
    }

    @Override
    public String getStatusMsg() {
      return statusMsg;
    }

    @Override
    public String getName() {
      return "TestCommand";
    }
  }

  @Test
  @DisplayName("Adversarial: runCommand throws TransactionExecutionException on command failure")
  void testRunCommandFailure() {
    var session = new GhidraSession(new TestScript());

    // Normal failure with status message
    var cmd = new TestCommand(false, "address out of bounds");
    var ex = assertThrows(TransactionExecutionException.class, () ->
        session.runCommand(cmd, "unable to write memory"));
    assertEquals("unable to write memory: address out of bounds", ex.getMessage());
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
  }

  @Test
  @DisplayName("Adversarial: runCommand handles null, empty, and blank statusMsg with fallback")
  void testRunCommandBlankStatusMsg() {
    var session = new GhidraSession(new TestScript());

    // Null statusMsg
    var cmdNull = new TestCommand(false, null);
    var exNull = assertThrows(TransactionExecutionException.class, () ->
        session.runCommand(cmdNull, "patch failed"));
    assertEquals("patch failed: command failed", exNull.getMessage());

    // Empty statusMsg
    var cmdEmpty = new TestCommand(false, "");
    var exEmpty = assertThrows(TransactionExecutionException.class, () ->
        session.runCommand(cmdEmpty, "patch failed"));
    assertEquals("patch failed: command failed", exEmpty.getMessage());

    // Blank whitespace statusMsg
    var cmdBlank = new TestCommand(false, "   \t\n  ");
    var exBlank = assertThrows(TransactionExecutionException.class, () ->
        session.runCommand(cmdBlank, "patch failed"));
    assertEquals("patch failed: command failed", exBlank.getMessage());
  }

  @Test
  @DisplayName("Adversarial: runCommand handles extremely long status message")
  void testRunCommandHugeStatusMsg() {
    var session = new GhidraSession(new TestScript());
    String hugeStatus = "X".repeat(100_000);
    var cmd = new TestCommand(false, hugeStatus);

    var ex = assertThrows(TransactionExecutionException.class, () ->
        session.runCommand(cmd, "prefix"));
    assertEquals("prefix: " + hugeStatus, ex.getMessage());
  }

  @Test
  @DisplayName("Adversarial: runCommand succeeds with valid command")
  void testRunCommandSuccess() {
    var session = new GhidraSession(new TestScript());
    var cmd = new TestCommand(true, "ok");
    // Should not throw
    session.runCommand(cmd, "prefix");
  }

  @Test
  @DisplayName("Adversarial: withTransaction propagates RuntimeException directly (no double-wrapping)")
  void testWithTransactionPropagatesRuntimeException() {
    var session = new GhidraSession(new TestScript());

    // Client parameter error (IllegalArgumentException) must NOT become TransactionExecutionException
    var clientEx = new IllegalArgumentException("invalid register name: R99");
    var thrownClient = assertThrows(IllegalArgumentException.class, () ->
        session.withTransaction(() -> { throw clientEx; }));
    assertSame(clientEx, thrownClient);

    // IllegalStateException
    var stateEx = new IllegalStateException("program not initialized");
    var thrownState = assertThrows(IllegalStateException.class, () ->
        session.withTransaction(() -> { throw stateEx; }));
    assertSame(stateEx, thrownState);

    // Existing TransactionExecutionException
    var txEx = new TransactionExecutionException("already tx ex");
    var thrownTx = assertThrows(TransactionExecutionException.class, () ->
        session.withTransaction(() -> { throw txEx; }));
    assertSame(txEx, thrownTx);
  }

  @Test
  @DisplayName("Adversarial: withTransaction wraps checked Exception into TransactionExecutionException")
  void testWithTransactionWrapsCheckedException() {
    var session = new GhidraSession(new TestScript());

    var ioEx = new IOException("corrupt program database file");
    var thrown = assertThrows(TransactionExecutionException.class, () ->
        session.withTransaction(() -> { throw ioEx; }));

    assertEquals("corrupt program database file", thrown.getMessage());
    assertSame(ioEx, thrown.getCause());
    assertEquals(500, thrown.status());
    assertEquals("transaction_failed", thrown.code());
  }

  @Test
  @DisplayName("Adversarial: Transaction depth and locks never leak across 2,000 repeated failures")
  void testRepeatedFailuresTransactionDepthHygiene() {
    var session = new GhidraSession(new TestScript());

    for (int i = 0; i < 2_000; i++) {
      final int iteration = i;
      if (iteration % 2 == 0) {
        assertThrows(IllegalArgumentException.class, () ->
            session.withTransaction(() -> { throw new IllegalArgumentException("client err " + iteration); }));
      } else {
        assertThrows(TransactionExecutionException.class, () ->
            session.withTransaction(() -> { throw new IOException("io err " + iteration); }));
      }

      // Invariant check: withTemporaryChanges requires transactionDepth == 0
      // If transactionDepth leaked, this would throw IllegalStateException!
      String testResult = session.withTemporaryChanges(() -> "depth_is_zero");
      assertEquals("depth_is_zero", testResult);
    }
  }

  @Test
  @DisplayName("Adversarial: Nested transaction rejection for temporary changes does not leak depth")
  void testNestedTransactionDepthHygiene() {
    var session = new GhidraSession(new TestScript());

    assertThrows(IllegalStateException.class, () ->
        session.withTransaction(() -> {
          // Inner temporary changes are forbidden inside outer transaction
          session.withTemporaryChanges(() -> "illegal");
          return null;
        }));

    // Verify outer depth was restored to 0
    String result = session.withTemporaryChanges(() -> "clean");
    assertEquals("clean", result);
  }

  @Test
  @DisplayName("Adversarial: High concurrency stress (20 threads, 2000 total ops) ensures thread safety and no deadlock")
  void testConcurrentTransactionsNoDeadlock() throws Exception {
    var session = new GhidraSession(new TestScript());
    int threads = 20;
    int opsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(threads);
    CountDownLatch startLatch = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();
    AtomicInteger successfulTransactions = new AtomicInteger(0);

    for (int t = 0; t < threads; t++) {
      final int threadId = t;
      futures.add(executor.submit(() -> {
        try {
          startLatch.await();
          for (int i = 0; i < opsPerThread; i++) {
            final int opIndex = i;
            int mode = (threadId + opIndex) % 4;
            switch (mode) {
              case 0 -> {
                String res = session.withTransaction(() -> "success_" + threadId + "_" + opIndex);
                assertNotNull(res);
                successfulTransactions.incrementAndGet();
              }
              case 1 -> {
                assertThrows(IllegalArgumentException.class, () ->
                    session.withTransaction(() -> { throw new IllegalArgumentException("fail"); }));
              }
              case 2 -> {
                assertThrows(TransactionExecutionException.class, () ->
                    session.withTransaction(() -> { throw new IOException("io fail"); }));
              }
              case 3 -> {
                var cmd = new TestCommand(true, "ok");
                session.runCommand(cmd, "run");
              }
            }
          }
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      }));
    }

    startLatch.countDown();
    for (Future<?> f : futures) {
      f.get(10, TimeUnit.SECONDS);
    }
    executor.shutdown();
    assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

    // Verify final state: session remains fully operational and unlocked
    String finalCheck = session.withTemporaryChanges(() -> "verified_operational");
    assertEquals("verified_operational", finalCheck);
  }
}
