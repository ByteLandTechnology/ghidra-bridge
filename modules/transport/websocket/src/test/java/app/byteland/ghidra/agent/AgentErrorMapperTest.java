package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import app.byteland.ghidra.service.TransactionExecutionException;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentErrorMapperTest {

  @Test
  @DisplayName("Maps TransactionExecutionException to 500 transaction_failed inside RPC error data")
  void testMapsTransactionExecutionExceptionTo500InRpcResponse() {
    var ex = new TransactionExecutionException("unable to remove parameter: command failed");
    var response = AgentErrorMapper.errorResponse("req-42", ex);

    assertEquals("req-42", response.id());
    assertNotNull(response.error());
    assertEquals(-32000, response.error().code());
    assertEquals("unable to remove parameter: command failed", response.error().message());

    Map<String, Object> data = response.error().data();
    assertEquals(500, data.get("status"));
    assertEquals("transaction_failed", data.get("code"));
    assertEquals("unable to remove parameter: command failed", data.get("message"));
  }

  @Test
  @DisplayName("Maps IllegalArgumentException to 400 invalid_request inside RPC error data")
  void testMapsIllegalArgumentExceptionTo400InRpcResponse() {
    var ex = new IllegalArgumentException("name is required");
    var response = AgentErrorMapper.errorResponse("req-43", ex);

    assertEquals("req-43", response.id());
    assertNotNull(response.error());
    assertEquals(-32000, response.error().code());
    assertEquals("name is required", response.error().message());

    Map<String, Object> data = response.error().data();
    assertEquals(400, data.get("status"));
    assertEquals("invalid_request", data.get("code"));
    assertEquals("name is required", data.get("message"));
  }
}
