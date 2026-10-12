package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.TransactionExecutionException;
import java.io.IOException;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ApiFailuresTest {
  @Test
  void unexpectedFailuresKeepPathsAndCredentialsPrivate() {
    var failure = ApiFailures.normalize(new java.io.IOException("/private/project Bearer TEST_SECRET"));
    assertEquals(500, failure.status());
    assertEquals("Internal error", failure.error().message());
    assertEquals(Map.of(), failure.error().details());
  }

  @Test
  @DisplayName("TransactionExecutionException maps to 500 transaction_failed")
  void testTransactionExecutionExceptionBasic() {
    var ex = new TransactionExecutionException("unable to remove parameter: command failed");
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("unable to remove parameter: command failed", failure.error().message());
    assertNull(failure.error().target());
    assertTrue(failure.error().details().isEmpty());
  }

  @Test
  @DisplayName("TransactionExecutionException preserves cause chaining")
  void testTransactionExecutionExceptionWithCause() {
    var cause = new IOException("database lock timeout");
    var ex = new TransactionExecutionException("transaction aborted", cause);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("transaction aborted", failure.error().message());
    assertEquals(cause, ex.getCause());
  }

  @Test
  @DisplayName("TransactionExecutionException preserves target and pointer conversion")
  void testTransactionExecutionExceptionWithTarget() {
    var ex = new TransactionExecutionException(
        "variable storage collision", "parameters[0]");
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("variable storage collision", failure.error().message());
    assertEquals("/parameters/0", failure.error().target());
  }

  @Test
  @DisplayName("TransactionExecutionException preserves structured details map")
  void testTransactionExecutionExceptionWithDetails() {
    Map<String, Object> details = Map.of(
        "command", "SetFlowOverrideCmd",
        "retryable", false);
    var ex = new TransactionExecutionException(
        "flow override mutation failed", null, details, null);
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("transaction_failed", failure.error().code());
    assertEquals("flow override mutation failed", failure.error().message());
    assertEquals("SetFlowOverrideCmd", failure.error().details().get("command"));
    assertEquals(false, failure.error().details().get("retryable"));
  }

  @Test
  @DisplayName("IllegalArgumentException maps strictly to 400 invalid_request")
  void testIllegalArgumentExceptionMappedTo400() {
    var ex = new IllegalArgumentException("invalid address format: 0xZZZZ");
    var failure = ApiFailures.normalize(ex);

    assertEquals(400, failure.status());
    assertEquals("invalid_request", failure.error().code());
    assertEquals("invalid address format: 0xZZZZ", failure.error().message());
    assertNull(failure.error().target());
  }

  @Test
  @DisplayName("IllegalStateException maps to 500 internal_error with a safe message")
  void testIllegalStateExceptionPreservesMessage() {
    var ex = new IllegalStateException("No current program is open in Ghidra");
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("internal_error", failure.error().code());
    assertEquals("Internal error", failure.error().message());
  }

  @Test
  @DisplayName("NoSuchElementException maps to 404 resource_not_found")
  void testNoSuchElementExceptionMappedTo404() {
    var ex = new NoSuchElementException("function symbol not found: main");
    var failure = ApiFailures.normalize(ex);

    assertEquals(404, failure.status());
    assertEquals("resource_not_found", failure.error().code());
    assertEquals("function symbol not found: main", failure.error().message());
  }

  @Test
  @DisplayName("SecurityException maps to 403 access_forbidden with fixed message")
  void testSecurityExceptionMappedTo403() {
    var ex = new SecurityException("unauthorized token");
    var failure = ApiFailures.normalize(ex);

    assertEquals(403, failure.status());
    assertEquals("access_forbidden", failure.error().code());
    assertEquals("Access forbidden", failure.error().message());
  }

  @Test
  @DisplayName("TimeoutException maps to 408 operation_timed_out")
  void testTimeoutExceptionMappedTo408() {
    var ex = new TimeoutException("session lease expired");
    var failure = ApiFailures.normalize(ex);

    assertEquals(408, failure.status());
    assertEquals("operation_timed_out", failure.error().code());
    assertEquals("session lease expired", failure.error().message());
  }

  @Test
  @DisplayName("Fallback unhandled RuntimeException maps to 500 internal_error with a safe message")
  void testUnhandledRuntimeExceptionPreservesMessage() {
    var ex = new RuntimeException("Unexpected NullPointerException at ListingModel.java:42");
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("internal_error", failure.error().code());
    assertEquals("Internal error", failure.error().message());
  }

  @Test
  @DisplayName("Fallback unhandled RuntimeException with blank message uses a safe message")
  void testUnhandledRuntimeExceptionWithBlankMessage() {
    var ex = new RuntimeException("   ");
    var failure = ApiFailures.normalize(ex);

    assertEquals(500, failure.status());
    assertEquals("internal_error", failure.error().code());
    assertEquals("Internal error", failure.error().message());
  }

  @Test
  @DisplayName("ApiException maps directly using its status and BridgeError")
  void testApiExceptionNormalization() {
    var bridgeError = new BridgeError(409, "batch_rolled_back", "atomic batch failed", null, Map.of());
    var apiException = new ApiException(409, bridgeError);
    var failure = ApiFailures.normalize(apiException);

    assertEquals(409, failure.status());
    assertEquals("batch_rolled_back", failure.error().code());
    assertEquals("atomic batch failed", failure.error().message());
  }
}
