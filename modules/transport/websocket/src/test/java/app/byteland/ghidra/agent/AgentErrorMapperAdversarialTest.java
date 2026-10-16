package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.TransactionExecutionException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentErrorMapperAdversarialTest {

  @Test
  @DisplayName("Adversarial: errorResponse maps null and blank messages and does not throw")
  void testErrorResponseBlankMessageSafety() {
    var exNull = new RuntimeException((String) null);
    var resNull = AgentErrorMapper.errorResponse("req-null", exNull);
    assertEquals("req-null", resNull.id());
    assertEquals("Internal error", resNull.error().message());
    assertEquals(500, resNull.error().data().get("status"));
    assertEquals("internal_error", resNull.error().data().get("code"));

    var exBlank = new IllegalArgumentException("   ");
    var resBlank = AgentErrorMapper.errorResponse(999, exBlank);
    assertEquals(999, resBlank.id());
    assertEquals("java.lang.IllegalArgumentException", resBlank.error().message());
    assertEquals(400, resBlank.error().data().get("status"));
    assertEquals("invalid_request", resBlank.error().data().get("code"));
  }

  @Test
  @DisplayName("Adversarial: errorResponse maps TransactionExecutionException with target and details map")
  void testErrorResponseTransactionExecutionExceptionComplete() {
    Map<String, Object> details = Map.of(
        "opcode", "CALL",
        "retryable", false,
        "offset", 0x1000L);
    var ex = new TransactionExecutionException(
        "failed to patch instruction",
        "instructions[4].bytes",
        details,
        new IOException("storage read only"));

    var res = AgentErrorMapper.errorResponse("tx-req-1", ex);
    assertEquals("tx-req-1", res.id());
    assertEquals(-32000, res.error().code());
    assertEquals("failed to patch instruction", res.error().message());

    Map<String, Object> data = res.error().data();
    assertEquals(500, data.get("status"));
    assertEquals("transaction_failed", data.get("code"));
    assertEquals("failed to patch instruction", data.get("message"));
    assertEquals("/instructions/4/bytes", data.get("target"));

    @SuppressWarnings("unchecked")
    Map<String, Object> detailsOut = (Map<String, Object>) data.get("details");
    assertNotNull(detailsOut);
    assertEquals("CALL", detailsOut.get("opcode"));
    assertEquals(false, detailsOut.get("retryable"));
    assertEquals(0x1000L, detailsOut.get("offset"));

    // Check the JSON-RPC toMap serialization.
    Map<String, Object> rpcMap = res.toMap();
    assertEquals("2.0", rpcMap.get("jsonrpc"));
    assertEquals("tx-req-1", rpcMap.get("id"));
    assertTrue(rpcMap.containsKey("error"));
    assertFalse(rpcMap.containsKey("result"));
  }

  private void assertFalse(boolean containsKey) {
    org.junit.jupiter.api.Assertions.assertFalse(containsKey);
  }

  @Test
  @DisplayName("Adversarial: high-concurrency errorResponse test (50 threads, 5,000 operations)")
  void testConcurrentErrorMapping() throws Exception {
    int threads = 50;
    int opsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(threads);
    CountDownLatch startLatch = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();

    for (int t = 0; t < threads; t++) {
      final int threadId = t;
      futures.add(executor.submit(() -> {
        try {
          startLatch.await();
          for (int i = 0; i < opsPerThread; i++) {
            Exception ex = (i % 2 == 0)
                ? new TransactionExecutionException("tx failure " + i)
                : new IllegalArgumentException("arg failure " + i);
            var res = AgentErrorMapper.errorResponse("id-" + threadId + "-" + i, ex);
            assertNotNull(res);
            assertEquals("id-" + threadId + "-" + i, res.id());
            assertEquals(-32000, res.error().code());
            assertNotNull(res.error().data().get("status"));
            assertNotNull(res.error().data().get("code"));
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
  }
}
