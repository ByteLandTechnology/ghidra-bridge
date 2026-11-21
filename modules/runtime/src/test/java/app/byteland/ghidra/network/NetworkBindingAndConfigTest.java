package app.byteland.ghidra.network;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.agent.AgentConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class NetworkBindingAndConfigTest {

  @Test
  @DisplayName("Server-mode AgentConfig requires non-blank token even on loopback")
  void serverModeAgentConfigRequiresTokenOnLoopback() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", null, "demo", null));
    assertThrows(
        IllegalArgumentException.class,
        () -> new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", "   ", "demo", null));
    assertThrows(
        IllegalArgumentException.class,
        () -> AgentConfig.fromArgs("host=127.0.0.1", "port=8765", "session_id=demo"));

    AgentConfig configured =
        AgentConfig.fromArgs(
            "host=127.0.0.1", "port=8765", "session_id=demo", "token=loopback-secret");
    assertTrue(configured.isServerMode());
    assertEquals("loopback-secret", configured.token());
  }

  @Test
  @DisplayName("Outbound client-mode AgentConfig still allows omitted token")
  void outboundAgentConfigAllowsOptionalToken() {
    AgentConfig outboundNoToken =
        AgentConfig.fromArgs("ws_url=ws://127.0.0.1:8765/ws/agent", "session_id=demo");
    assertTrue(outboundNoToken.isOutboundMode());
    assertNull(outboundNoToken.token());

    AgentConfig outboundWithToken =
        AgentConfig.fromArgs(
            "ws_url=ws://127.0.0.1:8765/ws/agent", "session_id=demo", "token=client-secret");
    assertEquals("client-secret", outboundWithToken.token());
  }

  @Test
  @DisplayName("bearerTokenMatches rejects null or blank expected/actual tokens and matches exact Bearer header")
  void bearerTokenMatchesChecks() {
    assertFalse(NetworkBinding.bearerTokenMatches(null, "secret"));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer secret", null));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer secret", "   "));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer wrong", "secret"));
    assertFalse(NetworkBinding.bearerTokenMatches("Basic secret", "secret"));
    assertTrue(NetworkBinding.bearerTokenMatches("Bearer secret", "secret"));
  }

  @Test
  @DisplayName("isAllowedHostHeader accepts loopback Host values and blocks DNS rebinding domains")
  void hostHeaderValidationBlocksDnsRebinding() {
    assertTrue(NetworkBinding.isAllowedHostHeader("127.0.0.1:8766", "127.0.0.1", 8766, true));
    assertTrue(NetworkBinding.isAllowedHostHeader("127.0.0.1", "127.0.0.1", 8766, true));
    assertTrue(NetworkBinding.isAllowedHostHeader("localhost:8766", "127.0.0.1", 8766, true));
    assertTrue(NetworkBinding.isAllowedHostHeader("LOCALHOST:8766", "127.0.0.1", 8766, true));
    assertTrue(NetworkBinding.isAllowedHostHeader("[::1]:8766", "127.0.0.1", 8766, true));
    assertTrue(NetworkBinding.isAllowedHostHeader("[::1]", "::1", 8766, true));

    assertFalse(
        NetworkBinding.isAllowedHostHeader(
            "rebind.example.invalid:8766", "127.0.0.1", 8766, true));
    assertFalse(
        NetworkBinding.isAllowedHostHeader("rebind.example.invalid", "127.0.0.1", 8766, true));
    assertFalse(
        NetworkBinding.isAllowedHostHeader("127.0.0.1.evil.invalid:8766", "127.0.0.1", 8766, true));
    assertFalse(
        NetworkBinding.isAllowedHostHeader("127.0.0.1@evil.invalid:8766", "127.0.0.1", 8766, true));
    assertFalse(NetworkBinding.isAllowedHostHeader("127.0.0.1:9999", "127.0.0.1", 8766, true));
    assertFalse(NetworkBinding.isAllowedHostHeader("", "127.0.0.1", 8766, true));
    assertFalse(NetworkBinding.isAllowedHostHeader(null, "127.0.0.1", 8766, true));

    assertTrue(
        NetworkBinding.isAllowedHostHeader("192.168.1.25:8766", "192.168.1.25", 8766, false));
    assertFalse(
        NetworkBinding.isAllowedHostHeader(
            "rebind.example.invalid:8766", "192.168.1.25", 8766, false));
  }
}
