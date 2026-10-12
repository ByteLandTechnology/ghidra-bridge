package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.service.DomainException;
import app.byteland.ghidra.service.TransactionExecutionException;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class WireStressTest {

  @Test
  @DisplayName("Stress: Null message fallback to class name without crash")
  void testNullMessageFallback() {
    var ex = new TransactionExecutionException(null);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("app.byteland.ghidra.service.TransactionExecutionException", failure.error().message());
    assertNull(failure.error().target());
    assertTrue(failure.error().details().isEmpty());

    Map<String, Object> map = failure.error().toMap();
    assertEquals(500, map.get("status"));
    assertEquals("transaction_failed", map.get("code"));
    assertEquals("app.byteland.ghidra.service.TransactionExecutionException", map.get("message"));
    assertFalse(map.containsKey("target"));
    assertFalse(map.containsKey("details"));
  }

  @Test
  @DisplayName("Stress: Blank message fallback to class name without crash")
  void testBlankMessageFallback() {
    var ex = new TransactionExecutionException("   \t\n  ");
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("app.byteland.ghidra.service.TransactionExecutionException", failure.error().message());
  }

  @Test
  @DisplayName("Stress: Unicode, emoji, quotes, newlines, and control characters")
  void testUnicodeAndSpecialCharactersInMessage() {
    String message = "Transaction failure: 事务失败 / 処理失敗 💥 \"quoted\" 'single' \n\t\r\\/$@!#";
    var ex = new TransactionExecutionException(message);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals(message, failure.error().message());
  }

  @Test
  @DisplayName("Stress: Very large error message (64 KiB)")
  void testLargeErrorMessage() {
    String longMsg = "A".repeat(65536);
    var ex = new TransactionExecutionException(longMsg);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals(65536, failure.error().message().length());
  }

  @Test
  @DisplayName("Stress: Deeply nested cause chain (10 levels)")
  void testDeeplyNestedCauseChain() {
    Throwable current = new IOException("root socket closed");
    for (int i = 0; i < 9; i++) {
      current = new RuntimeException("wrapped level " + i, current);
    }
    var ex = new TransactionExecutionException("transaction aborted due to io", current);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("transaction aborted due to io", failure.error().message());
    assertNotNull(ex.getCause());
  }

  @Test
  @DisplayName("Stress: Target pointer conversions across diverse syntactic forms")
  void testTargetPointerConversions() {
    // Plain property
    var ex1 = new TransactionExecutionException("err", "paramName");
    assertEquals("/param_name", ApiFailures.normalize(ex1).error().target());

    // CamelCase property
    var ex2 = new TransactionExecutionException("err", "symbolAddress");
    assertEquals("/symbol_address", ApiFailures.normalize(ex2).error().target());

    // Nested dot property
    var ex3 = new TransactionExecutionException("err", "parent.child.subProperty");
    assertEquals("/parent/child/sub_property", ApiFailures.normalize(ex3).error().target());

    // Array index notation
    var ex4 = new TransactionExecutionException("err", "items[0]");
    assertEquals("/items/0", ApiFailures.normalize(ex4).error().target());

    // Mixed nested and array
    var ex5 = new TransactionExecutionException("err", "function.parameters[2].storage");
    assertEquals("/function/parameters/2/storage", ApiFailures.normalize(ex5).error().target());

    // Already leading slash pointer
    var ex6 = new TransactionExecutionException("err", "/already/pointer/format");
    assertEquals("/already/pointer/format", ApiFailures.normalize(ex6).error().target());

    // Null or blank target
    var ex7 = new TransactionExecutionException("err", (String) null);
    assertNull(ApiFailures.normalize(ex7).error().target());

    var ex8 = new TransactionExecutionException("err", "   ");
    assertEquals("   ", ApiFailures.normalize(ex8).error().target());
  }

  @Test
  @DisplayName("Stress: Complex structured details preservation and immutability")
  void testComplexDetailsPreservation() {
    Map<String, Object> details = new LinkedHashMap<>();
    details.put("command", "UpdateFunctionCmd");
    details.put("transactionId", 42);
    details.put("retryable", false);
    details.put("nested", Map.of("step", "apply_signature", "status", "failed"));
    details.put("list", List.of("reg1", "reg2"));

    var ex = new TransactionExecutionException("db conflict", null, details, null);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals(details, failure.error().details());

    Map<String, Object> wireMap = failure.error().toMap();
    assertTrue(wireMap.containsKey("details"));
    assertEquals(details, wireMap.get("details"));
  }

  @Test
  @DisplayName("Stress: Strict segregation between client 400 and internal 500")
  void testStrictSegregationClientVsInternal() {
    // Client parameter failures -> 400 invalid_request
    var clientErr = new IllegalArgumentException("invalid hex address: 0xINVALID");
    var clientNorm = ApiFailures.normalize(clientErr);
    assertEquals(400, clientNorm.status());
    assertEquals("invalid_request", clientNorm.error().code());

    // Ghidra transaction abort -> 500 transaction_failed
    var dbErr = new TransactionExecutionException("transaction rolled back: lock timeout");
    var dbNorm = ApiFailures.normalize(dbErr);
    assertEquals(500, dbNorm.status());
    assertEquals("transaction_failed", dbNorm.error().code());

    // Internal state failure -> 500 internal_error
    var stateErr = new IllegalStateException("Program is closed");
    var stateNorm = ApiFailures.normalize(stateErr);
    assertEquals(500, stateNorm.status());
    assertEquals("internal_error", stateNorm.error().code());

    // Null pointer failure -> 500 internal_error
    var npeErr = new NullPointerException("memory address space null");
    var npeNorm = ApiFailures.normalize(npeErr);
    assertEquals(500, npeNorm.status());
    assertEquals("internal_error", npeNorm.error().code());
  }

  @Test
  @DisplayName("Stress: Wire JSON-RPC envelope generation matches protocol specification")
  void testJsonRpcEnvelopeCompatibility() {
    var ex = new TransactionExecutionException("symbol conflict at address", "symbol.name");
    var failure = ApiFailures.normalize(ex);

    Map<String, Object> rpcResponse = JsonRpc.errorResponse(
        "req-999", -32000, failure.error().message(), failure.error().toMap());

    assertEquals("2.0", rpcResponse.get(JsonRpc.VERSION));
    assertEquals("req-999", rpcResponse.get(JsonRpc.ID));

    @SuppressWarnings("unchecked")
    Map<String, Object> errorObj = (Map<String, Object>) rpcResponse.get(JsonRpc.ERROR);
    assertNotNull(errorObj);
    assertEquals(-32000, errorObj.get(JsonRpc.CODE));
    assertEquals("symbol conflict at address", errorObj.get(JsonRpc.MESSAGE));

    @SuppressWarnings("unchecked")
    Map<String, Object> dataObj = (Map<String, Object>) errorObj.get(JsonRpc.DATA);
    assertNotNull(dataObj);
    assertEquals(500, dataObj.get("status"));
    assertEquals("transaction_failed", dataObj.get("code"));
    assertEquals("symbol conflict at address", dataObj.get("message"));
    assertEquals("/symbol/name", dataObj.get("target"));
  }
}
