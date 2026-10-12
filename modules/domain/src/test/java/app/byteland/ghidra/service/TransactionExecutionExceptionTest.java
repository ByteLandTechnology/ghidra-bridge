package app.byteland.ghidra.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TransactionExecutionExceptionTest {

  @Test
  @DisplayName("Constructor with message only")
  void testConstructorWithMessage() {
    var ex = new TransactionExecutionException("transaction aborted");
    assertEquals("transaction aborted", ex.getMessage());
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
    assertNull(ex.target());
    assertNull(ex.getCause());
    assertTrue(ex.details().isEmpty());
    assertTrue(ex instanceof DomainException);
  }

  @Test
  @DisplayName("Constructor with message and cause")
  void testConstructorWithMessageAndCause() {
    var cause = new IOException("io failure");
    var ex = new TransactionExecutionException("transaction aborted", cause);
    assertEquals("transaction aborted", ex.getMessage());
    assertSame(cause, ex.getCause());
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
    assertNull(ex.target());
    assertTrue(ex.details().isEmpty());
  }

  @Test
  @DisplayName("Constructor with message and target")
  void testConstructorWithMessageAndTarget() {
    var ex = new TransactionExecutionException("failed", "target1");
    assertEquals("failed", ex.getMessage());
    assertEquals("target1", ex.target());
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
    assertNull(ex.getCause());
    assertTrue(ex.details().isEmpty());
  }

  @Test
  @DisplayName("Constructor with message, target, and cause")
  void testConstructorWithMessageTargetAndCause() {
    var cause = new RuntimeException("inner");
    var ex = new TransactionExecutionException("failed", "target2", cause);
    assertEquals("failed", ex.getMessage());
    assertEquals("target2", ex.target());
    assertSame(cause, ex.getCause());
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
  }

  @Test
  @DisplayName("Constructor with message and details")
  void testConstructorWithMessageAndDetails() {
    Map<String, Object> map = new HashMap<>();
    map.put("key", "value");
    var ex = new TransactionExecutionException("failed", map);
    assertEquals("failed", ex.getMessage());
    assertEquals("value", ex.details().get("key"));
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
    assertNull(ex.target());
    assertNull(ex.getCause());

    // Verify defensive copy and immutability
    map.put("key2", "value2");
    assertNull(ex.details().get("key2"));
    assertThrows(UnsupportedOperationException.class, () -> ex.details().put("x", "y"));
  }

  @Test
  @DisplayName("Constructor with message, details, and cause")
  void testConstructorWithMessageDetailsAndCause() {
    var cause = new IllegalStateException("db busy");
    Map<String, Object> map = Map.of("retryCount", 3);
    var ex = new TransactionExecutionException("failed", map, cause);
    assertEquals("failed", ex.getMessage());
    assertSame(cause, ex.getCause());
    assertEquals(3, ex.details().get("retryCount"));
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
  }

  @Test
  @DisplayName("Full constructor with message, target, details, and cause")
  void testFullConstructor() {
    var cause = new IllegalArgumentException("bad");
    Map<String, Object> map = Map.of("step", 2);
    var ex = new TransactionExecutionException("failed", "var1", map, cause);
    assertEquals("failed", ex.getMessage());
    assertEquals("var1", ex.target());
    assertSame(cause, ex.getCause());
    assertEquals(2, ex.details().get("step"));
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
  }

  @Test
  @DisplayName("Null details safely produces empty map")
  void testNullDetailsSafety() {
    var ex = new TransactionExecutionException("failed", "t", null, null);
    assertNotNull(ex.details());
    assertTrue(ex.details().isEmpty());
  }
}
