package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.network.NetworkBinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentConfigTest {

  @Test
  @DisplayName("Server-mode AgentConfig requires a non-blank token on loopback and non-loopback hosts")
  void testServerModeRequiresTokenEvenOnLoopback() {
    String[] hosts = {null, "127.0.0.1", "localhost", "::1", "0.0.0.0"};
    String[] invalidTokens = {null, "", "   \t\n"};

    for (String host : hosts) {
      for (String invalidToken : invalidTokens) {
        IllegalArgumentException error =
            assertThrows(
                IllegalArgumentException.class,
                () -> new AgentConfig(null, host, 8765, "/ws/agent", invalidToken, "demo", null));
        assertEquals("token is required", error.getMessage());
      }
    }

    IllegalArgumentException fromArgsMissing =
        assertThrows(
            IllegalArgumentException.class,
            () -> AgentConfig.fromArgs("host=127.0.0.1", "port=8765", "session_id=demo"));
    assertEquals("token is required", fromArgsMissing.getMessage());

    IllegalArgumentException fromArgsBlank =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "host=127.0.0.1", "port=8765", "session_id=demo", "token=   "));
    assertEquals("token is required", fromArgsBlank.getMessage());
  }

  @Test
  @DisplayName("Server-mode AgentConfig accepts non-blank tokens on loopback and external hosts")
  void testServerModeAcceptsConfiguredToken() {
    AgentConfig loopback =
        AgentConfig.fromArgs(
            "host=127.0.0.1", "port=8765", "path=/ws/agent", "session_id=demo", "token=secret-1");
    assertTrue(loopback.isServerMode());
    assertFalse(loopback.isOutboundMode());
    assertEquals("127.0.0.1", loopback.host());
    assertEquals(8765, loopback.port());
    assertEquals("/ws/agent", loopback.path());
    assertEquals("secret-1", loopback.token());
    assertEquals("demo", loopback.sessionId());

    AgentConfig external =
        AgentConfig.fromArgs("host=0.0.0.0", "port=9000", "session_id=ext", "token=  secret-2  ");
    assertTrue(external.isServerMode());
    assertEquals("0.0.0.0", external.host());
    assertEquals(9000, external.port());
    assertEquals("secret-2", external.token());
  }

  @Test
  @DisplayName("Outbound client mode still permits omitted token")
  void testOutboundModeAllowsOmittedToken() {
    AgentConfig outbound =
        AgentConfig.fromArgs("ws_url=ws://127.0.0.1:8765/ws/agent", "session_id=demo");
    assertTrue(outbound.isOutboundMode());
    assertFalse(outbound.isServerMode());
    assertNull(outbound.token());
  }

  @Test
  @DisplayName("NetworkBinding.bearerTokenMatches enforces non-blank expected token and exact Bearer match")
  void testBearerTokenMatches() {
    assertTrue(NetworkBinding.bearerTokenMatches("Bearer secret-token", "secret-token"));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer wrong-token", "secret-token"));
    assertFalse(NetworkBinding.bearerTokenMatches("bearer secret-token", "secret-token"));
    assertFalse(NetworkBinding.bearerTokenMatches("Basic secret-token", "secret-token"));
    assertFalse(NetworkBinding.bearerTokenMatches("secret-token", "secret-token"));
    assertFalse(NetworkBinding.bearerTokenMatches(null, "secret-token"));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer null", null));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer ", ""));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer    ", "   "));
  }
}
