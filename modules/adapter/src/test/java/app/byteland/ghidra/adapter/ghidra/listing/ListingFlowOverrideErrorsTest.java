package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.DomainException;
import app.byteland.ghidra.service.TransactionExecutionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ListingFlowOverrideErrorsTest {

  @Test
  @DisplayName("ListingFlowOverrideErrors.conflict creates DomainException with 409 conflict")
  void testConflictError() {
    var ex = ListingFlowOverrideErrors.conflict("expected BRANCH but found CALL");
    assertTrue(ex instanceof DomainException);
    var domain = (DomainException) ex;
    assertEquals(409, domain.status());
    assertEquals("conflict", domain.code());
    assertNull(domain.target());
    assertEquals("expected BRANCH but found CALL", ex.getMessage());
  }

  @Test
  @DisplayName("ListingFlowOverrideErrors.updateFailed creates TransactionExecutionException with 500 transaction_failed")
  void testUpdateFailedError() {
    var ex = ListingFlowOverrideErrors.updateFailed("unable to set flow override");
    assertTrue(ex instanceof TransactionExecutionException);
    assertTrue(ex instanceof DomainException);
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
    assertEquals("unable to set flow override", ex.getMessage());
  }

  @Test
  @DisplayName("ListingFlowOverrideErrors.updateFailed preserves cause")
  void testUpdateFailedWithCause() {
    var cause = new IllegalArgumentException("command failed");
    var ex = ListingFlowOverrideErrors.updateFailed("mutation failed", cause);
    assertTrue(ex instanceof TransactionExecutionException);
    assertEquals(500, ex.status());
    assertEquals("transaction_failed", ex.code());
    assertSame(cause, ex.getCause());
    assertEquals("mutation failed", ex.getMessage());
  }
}
