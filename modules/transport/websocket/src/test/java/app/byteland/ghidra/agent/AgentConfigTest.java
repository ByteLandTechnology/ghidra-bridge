package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.network.NetworkBinding;
import java.util.Map;
import org.junit.jupiter.api.Test;

class AgentConfigTest {
  @Test
  void parsesEmbeddedServerDefaultsAndCustomPath() {
    AgentConfig defaults =
        AgentConfig.fromArgs("port=8765", "session_id=demo", "jar=/opt/ghidra-bridge.jar");
    assertTrue(defaults.isServerMode());
    assertFalse(defaults.isOutboundMode());
    assertNull(defaults.wsUrl());
    assertEquals(NetworkBinding.DEFAULT_LOOPBACK_HOST, defaults.host());
    assertEquals(8765, defaults.port());
    assertEquals("/ws/agent", defaults.path());
    assertNull(defaults.token());
    assertEquals("demo", defaults.sessionId());
    assertNull(defaults.exitDeadlineSeconds());
    assertNull(defaults.redactedWsUrl());

    AgentConfig custom =
        AgentConfig.fromArgs(
            "host=0.0.0.0",
            "port=9000",
            "path=custom/ws",
            "token=s3cr3t",
            "session_id=remote-demo");
    assertEquals("0.0.0.0", custom.host());
    assertEquals(9000, custom.port());
    assertEquals("/custom/ws", custom.path());
    assertEquals("s3cr3t", custom.token());
    assertEquals("remote-demo", custom.sessionId());
  }

  @Test
  void parsesOutboundClientModeAndRedactsWsUrl() {
    AgentConfig outbound =
        AgentConfig.fromArgs(
            "ws_url=ws://127.0.0.1:18489/ws/agent?token=secret#frag",
            "session_id=md5-session",
            "token=bearer-secret",
            "exit_deadline_sec=10");
    assertTrue(outbound.isOutboundMode());
    assertFalse(outbound.isServerMode());
    assertNull(outbound.host());
    assertNull(outbound.port());
    assertEquals("md5-session", outbound.sessionId());
    assertEquals("bearer-secret", outbound.token());
    assertEquals(10, outbound.exitDeadlineSeconds());
    assertEquals("ws://127.0.0.1:18489/ws/agent?<redacted>", outbound.redactedWsUrl());

    AgentConfig fragmentOnly =
        AgentConfig.fromArgs("ws_url=ws://127.0.0.1:18489/ws/agent#secret", "session_id=s1");
    assertEquals("ws://127.0.0.1:18489/ws/agent?<redacted>", fragmentOnly.redactedWsUrl());

    AgentConfig cleanUrl =
        AgentConfig.fromArgs("ws_url=ws://127.0.0.1:18489/ws/agent", "session_id=s1");
    assertEquals("ws://127.0.0.1:18489/ws/agent", cleanUrl.redactedWsUrl());
  }

  @Test
  void rejectsInvalidModeCombinationsAndSecurityViolations() {
    assertEquals(
        "session_id is required",
        assertThrows(IllegalArgumentException.class, () -> AgentConfig.fromArgs("port=8765"))
            .getMessage());

    assertEquals(
        "either ws_url or port is required",
        assertThrows(IllegalArgumentException.class, () -> AgentConfig.fromArgs("session_id=demo"))
            .getMessage());

    assertEquals(
        "ws_url conflicts with host/port/path",
        assertThrows(
                IllegalArgumentException.class,
                () ->
                    AgentConfig.fromArgs(
                        "ws_url=ws://127.0.0.1:8765/ws/agent", "port=8765", "session_id=demo"))
            .getMessage());

    assertEquals(
        "ws_url conflicts with host/port/path",
        assertThrows(
                IllegalArgumentException.class,
                () ->
                    AgentConfig.fromArgs(
                        "ws_url=ws://127.0.0.1:8765/ws/agent", "path=/ws/agent", "session_id=demo"))
            .getMessage());

    assertEquals(
        "token is required when binding outside loopback",
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentConfig.fromArgs("host=0.0.0.0", "port=8765", "session_id=demo"))
            .getMessage());

    assertEquals(
        "exit_deadline_sec requires ws_url",
        assertThrows(
                IllegalArgumentException.class,
                () ->
                    AgentConfig.fromArgs(
                        "port=8765", "session_id=demo", "exit_deadline_sec=5"))
            .getMessage());

    assertEquals(
        "exit_deadline_sec must be positive",
        assertThrows(
                IllegalArgumentException.class,
                () ->
                    AgentConfig.fromArgs(
                        "ws_url=ws://127.0.0.1:8765/ws/agent",
                        "session_id=demo",
                        "exit_deadline_sec=0"))
            .getMessage());

    assertEquals(
        "unknown startup argument: tool_prefix",
        assertThrows(
                IllegalArgumentException.class,
                () -> AgentConfig.fromMap(Map.of("port", "8765", "session_id", "d", "tool_prefix", "x")))
            .getMessage());
  }
}
