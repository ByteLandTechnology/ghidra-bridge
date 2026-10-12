package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.DomainException;
import app.byteland.ghidra.service.TransactionExecutionException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ApiFailuresAdversarialTest {

  @Test
  @DisplayName("Adversarial: Null, empty, and blank messages safely default to class name")
  void testNullEmptyBlankMessageHandling() {
    // Null message
    var exNull = new RuntimeException((String) null);
    var failureNull = ApiFailures.normalize(exNull);
    assertEquals(500, failureNull.status());
    assertEquals("internal_error", failureNull.error().code());
    assertEquals("Internal error", failureNull.error().message());

    // Empty message
    var exEmpty = new IllegalArgumentException("");
    var failureEmpty = ApiFailures.normalize(exEmpty);
    assertEquals(400, failureEmpty.status());
    assertEquals("invalid_request", failureEmpty.error().code());
    assertEquals("java.lang.IllegalArgumentException", failureEmpty.error().message());

    // Whitespace only message
    var exBlank = new TransactionExecutionException("   \t\n  ");
    var failureBlank = ApiFailures.normalize(exBlank);
    assertEquals(500, failureBlank.status());
    assertEquals("transaction_failed", failureBlank.error().code());
    assertEquals("app.byteland.ghidra.service.TransactionExecutionException", failureBlank.error().message());
  }

  @Test
  @DisplayName("Adversarial: Extremely long status message (500k chars) handled without overflow")
  void testExtremelyLongMessage() {
    String hugeMessage = "A".repeat(500_000);
    var ex = new TransactionExecutionException(hugeMessage);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals(500_000, failure.error().message().length());
    assertEquals(hugeMessage, failure.error().message());

    Map<String, Object> map = failure.error().toMap();
    assertEquals(500_000, ((String) map.get("message")).length());
  }

  @Test
  @DisplayName("Adversarial: Special characters, emojis, newlines, and JSON delimiters in messages")
  void testSpecialCharactersInMessages() {
    String special = "Error \u0000 with \"quotes\", \\backslashes\\, \nnewlines, \t tabs, and emojis: 🚀🔥💥 and unicode \u2028 \u2029";
    var ex = new TransactionExecutionException(special);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals(special, failure.error().message());

    Map<String, Object> map = failure.error().toMap();
    assertEquals(special, map.get("message"));
  }

  @Test
  @DisplayName("Adversarial: Deep nested causes chain (depth 500) preserves root and normalizes cleanly")
  void testDeepNestedCausesChain() {
    Throwable current = new SQLException("root db error");
    for (int i = 0; i < 500; i++) {
      current = new RuntimeException("wrapper " + i, current);
    }
    var topEx = new TransactionExecutionException("top transaction abort", current);

    var failure = ApiFailures.normalize(topEx);
    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("top transaction abort", failure.error().message());
    assertNotNull(topEx.getCause());
  }

  @Test
  @DisplayName("Adversarial: Complex pointer conversion for deeply nested and array targets")
  void testPointerConversionEdgeCases() {
    // Already pointer
    var ex1 = new TransactionExecutionException("err", "/already/a/pointer");
    assertEquals("/already/a/pointer", ApiFailures.normalize(ex1).error().target());

    // Null and blank targets
    var ex2 = new TransactionExecutionException("err", (String) null);
    assertNull(ApiFailures.normalize(ex2).error().target());

    var ex3 = new TransactionExecutionException("err", "   ");
    assertEquals("   ", ApiFailures.normalize(ex3).error().target());

    // Deep nested array indexing and CamelCase
    var ex4 = new TransactionExecutionException("err", "deeplyNestedObject.subFieldList[12].itemProperty");
    assertEquals("/deeply_nested_object/sub_field_list/12/item_property", ApiFailures.normalize(ex4).error().target());

    // Multiple consecutive separators
    var ex5 = new TransactionExecutionException("err", "foo..bar[[3]]");
    assertEquals("/foo/bar/3", ApiFailures.normalize(ex5).error().target());
  }

  @Test
  @DisplayName("Adversarial: Complex structured details preservation in TransactionExecutionException")
  void testStructuredDetailsPreservation() {
    Map<String, Object> details = new HashMap<>();
    details.put("stringValue", "failed_step");
    details.put("nestedMap", Map.of("subKey", 12345));
    details.put("listValue", List.of("a", "b", "c"));
    details.put("boolValue", true);
    details.put("longValue", 9876543210L);

    var ex = new TransactionExecutionException("detailed failure", "params[0]", details, new IOException("io"));
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("/params/0", failure.error().target());
    assertEquals(5, failure.error().details().size());
    assertEquals(true, failure.error().details().get("boolValue"));
    assertEquals(9876543210L, failure.error().details().get("longValue"));
  }

  @Test
  @DisplayName("Adversarial: Null value in details triggers NullPointerException due to BridgeError Map.copyOf")
  void testNullValueInDetailsFailsInBridgeError() {
    Map<String, Object> details = new HashMap<>();
    details.put("nullableKey", null);
    var ex = new TransactionExecutionException("failure with null detail value", details);

    // BridgeError constructor uses Map.copyOf(details), which does not permit null values
    org.junit.jupiter.api.Assertions.assertThrows(
        NullPointerException.class,
        () -> ApiFailures.normalize(ex));
  }

  @Test
  @DisplayName("Adversarial: Custom DomainException implementations map status and code cleanly")
  void testCustomDomainExceptions() {
    class CustomDomainException extends RuntimeException implements DomainException {
      private final int status;
      private final String code;
      private final String target;

      CustomDomainException(int status, String code, String target, String msg) {
        super(msg);
        this.status = status;
        this.code = code;
        this.target = target;
      }

      @Override public int status() { return status; }
      @Override public String code() { return code; }
      @Override public String target() { return target; }
    }

    var ex409 = new CustomDomainException(409, "conflict_error", "session_id", "conflict detected");
    var f409 = ApiFailures.normalize(ex409);
    assertEquals(409, f409.status());
    assertEquals("conflict_error", f409.error().code());
    assertEquals("/session_id", f409.error().target());
    assertEquals("conflict detected", f409.error().message());

    var ex422 = new CustomDomainException(422, "unprocessable_entity", null, "invalid entity");
    var f422 = ApiFailures.normalize(ex422);
    assertEquals(422, f422.status());
    assertEquals("unprocessable_entity", f422.error().code());
    assertNull(f422.error().target());
  }

  @Test
  @DisplayName("Adversarial: Strict segregation of 400 invalid_request vs 500 transaction_failed")
  void testStrictSegregationClientVsTransaction() {
    Throwable[] clientErrors = {
      new IllegalArgumentException("invalid argument: null pointer"),
      new IllegalArgumentException("out of range: 42 > 10"),
      new IllegalArgumentException("malformed token format")
    };

    for (Throwable t : clientErrors) {
      var failure = ApiFailures.normalize(t);
      assertEquals(400, failure.status(), "Client error must map to 400");
      assertEquals("invalid_request", failure.error().code());
    }

    Throwable[] transactionErrors = {
      new TransactionExecutionException("transaction aborted by db lock"),
      new TransactionExecutionException("Ghidra command rollback"),
      new TransactionExecutionException("unable to modify bytes in read-only section")
    };

    for (Throwable t : transactionErrors) {
      var failure = ApiFailures.normalize(t);
      assertEquals(500, failure.status(), "Transaction error must map to 500");
      assertEquals("transaction_failed", failure.error().code());
    }
  }

  @Test
  @DisplayName("Adversarial: High-concurrency normalization stress test (100 threads, 10,000 operations)")
  void testConcurrentNormalizationStress() throws Exception {
    int threadCount = 100;
    int opsPerThread = 100;
    ExecutorService executor = Executors.newFixedThreadPool(threadCount);
    CountDownLatch startLatch = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>();

    for (int t = 0; t < threadCount; t++) {
      final int threadId = t;
      futures.add(executor.submit(() -> {
        try {
          startLatch.await();
          for (int i = 0; i < opsPerThread; i++) {
            Throwable ex;
            switch ((threadId + i) % 6) {
              case 0 -> ex = new IllegalArgumentException("arg error " + i);
              case 1 -> ex = new TransactionExecutionException("tx error " + i, "target." + i);
              case 2 -> ex = new IllegalStateException("state error " + i);
              case 3 -> ex = new NoSuchElementException("not found " + i);
              case 4 -> ex = new TimeoutException("timeout " + i);
              default -> ex = new RuntimeException("generic " + i);
            }
            var failure = ApiFailures.normalize(ex);
            assertNotNull(failure);
            assertTrue(failure.status() >= 400 && failure.status() <= 500);
            assertNotNull(failure.error().code());
            assertNotNull(failure.error().message());
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
