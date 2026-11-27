package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.network.NetworkBinding;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
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
    assertEquals(
        "ws://" + NetworkBinding.DEFAULT_LOOPBACK_HOST + ":8765/ws/agent",
        defaults.serverEndpoint());

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
    assertEquals("ws://0.0.0.0:9000/custom/ws", custom.serverEndpoint());

    AgentConfig ipv6Server = new AgentConfig(null, "::1", 8765, "/ws/agent", null, "v6-demo", null);
    assertEquals("ws://[::1]:8765/ws/agent", ipv6Server.serverEndpoint());
  }

  @Test
  void parsesOutboundClientModeAndRedactsWsUrl() {
    AgentConfig outbound =
        AgentConfig.fromArgs(
            "ws_url=ws://127.0.0.1:18489/ws/agent?foo=bar#frag",
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
    assertNull(outbound.serverEndpoint());
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
                () -> AgentConfig.fromArgs("port=8765", "session_id=demo", "exit_deadline_sec=5"))
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
                () ->
                    AgentConfig.fromMap(
                        Map.of("port", "8765", "session_id", "d", "tool_prefix", "x")))
            .getMessage());
  }

  @Test
  @DisplayName("Rejects non-loopback ws_url when bearer token is omitted")
  void rejectsNonLoopbackWsUrlWithoutToken() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=ws://192.0.2.10:8765/ws/agent", "session_id=check-nonloopback"));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=ws://[2001:db8::1]:8765/ws/agent", "session_id=check-nonloopback-v6"));
  }

  @Test
  @DisplayName("Allows non-loopback ws_url when bearer token is provided")
  void allowsNonLoopbackWsUrlWithToken() {
    AgentConfig ipv4Config =
        AgentConfig.fromArgs(
            "ws_url=wss://192.0.2.10:8765/ws/agent",
            "token=header-bearer-token",
            "session_id=check-nonloopback-auth");
    assertTrue(ipv4Config.isOutboundMode());
    assertEquals("wss://192.0.2.10:8765/ws/agent", ipv4Config.redactedWsUrl());

    AgentConfig ipv6Config =
        AgentConfig.fromArgs(
            "ws_url=wss://[2001:db8::1]:8765/ws/agent",
            "token=header-bearer-token",
            "session_id=check-nonloopback-v6-auth");
    assertTrue(ipv6Config.isOutboundMode());
    assertEquals("wss://[2001:db8::1]:8765/ws/agent", ipv6Config.redactedWsUrl());
  }

  @Test
  @DisplayName("Allows IPv4 and IPv6 loopback ws_url without bearer token")
  void allowsLoopbackWsUrlsWithoutToken() {
    AgentConfig ipv4 =
        AgentConfig.fromArgs("ws_url=ws://127.0.0.1:8765/ws/agent", "session_id=loopback-v4");
    assertEquals("ws://127.0.0.1:8765/ws/agent", ipv4.redactedWsUrl());

    AgentConfig ipv6 =
        AgentConfig.fromArgs("ws_url=ws://[::1]:8765/ws/agent", "session_id=loopback-v6");
    assertEquals("ws://[::1]:8765/ws/agent", ipv6.redactedWsUrl());

    AgentConfig mcpSessionStyle =
        AgentConfig.fromArgs(
            "ws_url=ws://127.0.0.1:8765/ws/agent",
            "session_id=0123456789abcdef0123456789abcdef",
            "token=separate-agent-token",
            "exit_deadline_sec=30",
            "jar=/tmp/ghidra-bridge.jar");
    assertTrue(mcpSessionStyle.isOutboundMode());
    assertEquals(30, mcpSessionStyle.exitDeadlineSeconds());
  }

  @Test
  @DisplayName(
      "Rejects plain and percent-encoded token query parameters without leaking credentials")
  void rejectsQueryTokenParameters() {
    IllegalArgumentException plainEx =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://127.0.0.1:8765/ws/agent?token=marker-query-cred",
                    "session_id=check-query"));
    assertDoesNotContainSecret(plainEx, "marker-query-cred");

    IllegalArgumentException encodedEx =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://127.0.0.1:8765/ws/agent?%74oken=marker-encoded-cred",
                    "session_id=check-encoded-query"));
    assertDoesNotContainSecret(encodedEx, "marker-encoded-cred");

    IllegalArgumentException fullyEncodedEx =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://127.0.0.1:8765/ws/agent?foo=1&%74%6F%6B%65%6E=marker-full-cred",
                    "session_id=check-full-encoded-query"));
    assertDoesNotContainSecret(fullyEncodedEx, "marker-full-cred");

    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=ws://127.0.0.1:8765/ws/agent?token", "session_id=check-valueless-token"));
  }

  @Test
  @DisplayName("Rejects malformed percent-encoding in ws_url query without leaking credentials")
  void rejectsMalformedPercentEncodingWithoutLeakingCredentials() {
    IllegalArgumentException badHexEx =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://127.0.0.1:8765/ws/agent?foo=%ZZ&secret=marker-malformed-cred",
                    "session_id=check-bad-hex"));
    assertNull(badHexEx.getCause());
    assertDoesNotContainSecret(badHexEx, "marker-malformed-cred");

    IllegalArgumentException truncatedHexEx =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://127.0.0.1:8765/ws/agent?secret=marker-trunc-cred%2",
                    "session_id=check-trunc-hex"));
    assertNull(truncatedHexEx.getCause());
    assertDoesNotContainSecret(truncatedHexEx, "marker-trunc-cred");

    IllegalArgumentException invalidUtf8Ex =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://127.0.0.1:8765/ws/agent?foo=%FF&secret=marker-utf8-cred",
                    "session_id=check-bad-utf8"));
    assertNull(invalidUtf8Ex.getCause());
    assertDoesNotContainSecret(invalidUtf8Ex, "marker-utf8-cred");
  }

  @Test
  @DisplayName(
      "Rejects URI userinfo and omits credentials from redactedWsUrl and exception messages")
  void rejectsAndRedactsUserInfoWithoutLeakingCredentials() {
    String urlWithUserInfo = "ws://marker-user:marker-userinfo-cred@127.0.0.1:8765/ws/agent?foo=1";

    IllegalArgumentException userInfoEx =
        assertThrows(
            IllegalArgumentException.class,
            () -> AgentConfig.fromArgs("ws_url=" + urlWithUserInfo, "session_id=check-userinfo"));
    assertNull(userInfoEx.getCause());
    assertDoesNotContainSecret(userInfoEx, "marker-userinfo-cred");
    assertDoesNotContainSecret(userInfoEx, "marker-user");

    String redacted = AgentConfig.redactWsUrl(urlWithUserInfo);
    assertEquals("ws://127.0.0.1:8765/ws/agent?<redacted>", redacted);
    assertFalse(redacted.contains("marker-userinfo-cred"));
    assertFalse(redacted.contains("marker-user"));

    assertEquals(
        "ws://127.0.0.1:8765/ws/agent",
        AgentConfig.redactWsUrl("ws://marker-user:marker-userinfo-cred@127.0.0.1:8765/ws/agent"));
    assertEquals(
        "ws://[::1]:8765/ws/agent?<redacted>",
        AgentConfig.redactWsUrl("ws://marker-user:marker-userinfo-cred@[::1]:8765/ws/agent#frag"));
    assertEquals(
        "ws://127.0.0.1:8765/ws/@agent", AgentConfig.redactWsUrl("ws://127.0.0.1:8765/ws/@agent"));
    assertNull(AgentConfig.redactWsUrl(null));

    AgentConfig validWithQuery =
        AgentConfig.fromArgs(
            "ws_url=ws://127.0.0.1:8765/ws/agent?foo=marker-benign", "session_id=check-redact");
    assertEquals("ws://127.0.0.1:8765/ws/agent?<redacted>", validWithQuery.redactedWsUrl());

    IllegalArgumentException malformedUserInfoEx =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentConfig.fromArgs(
                    "ws_url=ws://marker-user:marker-userinfo-cred@127.0.0.1:8765/ws/agent?bad=%ZZ",
                    "session_id=check-malformed-userinfo"));
    assertNull(malformedUserInfoEx.getCause());
    assertDoesNotContainSecret(malformedUserInfoEx, "marker-userinfo-cred");
    assertDoesNotContainSecret(malformedUserInfoEx, "marker-user");
  }

  @Test
  @DisplayName("Rejects invalid schemes, missing hosts, and registry authorities")
  void rejectsInvalidSchemesAndRegistryAuthorities() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=http://127.0.0.1:8765/ws/agent", "session_id=check-http-scheme"));

    assertThrows(
        IllegalArgumentException.class,
        () -> AgentConfig.fromArgs("ws_url=ws:127.0.0.1:8765/ws/agent", "session_id=check-opaque"));

    assertThrows(
        IllegalArgumentException.class,
        () -> AgentConfig.fromArgs("ws_url=ws:///ws/agent", "session_id=check-missing-host"));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=ws://bad_host:8765/ws/agent", "session_id=check-registry-authority"));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=ws://@127.0.0.1:8765/ws/agent", "session_id=check-empty-userinfo"));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            AgentConfig.fromArgs(
                "ws_url=ws://127.0.0.1:70000/ws/agent", "session_id=check-invalid-port"));
  }

  private static void assertDoesNotContainSecret(Throwable error, String secret) {
    StringWriter buffer = new StringWriter();
    error.printStackTrace(new PrintWriter(buffer));
    String fullTrace = buffer.toString();
    assertFalse(
        fullTrace.contains(secret),
        () -> "Expected secret '" + secret + "' to be omitted from exception trace: " + fullTrace);
  }
}
