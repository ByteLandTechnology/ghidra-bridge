package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentWebSocketAuthTest {

  private static final String CONFIGURED_TOKEN = "test-session-bearer-token-256bit";
  private static final String SAMPLE_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
  private static final String SAMPLE_WS_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

  @Test
  @DisplayName("Validator rejects unauthenticated upgrade on loopback with HTTP 401")
  void testValidatorRejectsUnauthenticatedLoopbackUpgrade() {
    AgentConfig config =
        new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", CONFIGURED_TOKEN, "demo", null);
    WebSocketHandshake.HandshakeRequest originlessRequest =
        new WebSocketHandshake.HandshakeRequest(
            "GET", "/ws/agent", Map.of(), upgradeHeaders(null));

    WebSocketHandshake.HttpHandshakeException ex =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, originlessRequest));
    assertEquals(401, ex.status());
    assertEquals("Unauthorized", ex.reason());

    Map<String, String> loopbackOriginHeaders = upgradeHeaders(null);
    loopbackOriginHeaders.put("origin", "http://localhost:3000");
    WebSocketHandshake.HandshakeRequest loopbackOriginRequest =
        new WebSocketHandshake.HandshakeRequest(
            "GET", "/ws/agent", Map.of(), loopbackOriginHeaders);

    WebSocketHandshake.HttpHandshakeException loopbackOriginEx =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, loopbackOriginRequest));
    assertEquals(401, loopbackOriginEx.status());
    assertEquals("Unauthorized", loopbackOriginEx.reason());
  }

  @Test
  @DisplayName("Validator rejects mismatched bearer token and outbound null-token config with HTTP 401")
  void testValidatorRejectsInvalidBearerAndNullConfigToken() {
    AgentConfig serverConfig =
        new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", CONFIGURED_TOKEN, "demo", null);
    WebSocketHandshake.HandshakeRequest wrongTokenRequest =
        new WebSocketHandshake.HandshakeRequest(
            "GET", "/ws/agent", Map.of(), upgradeHeaders("Bearer wrong-token"));

    WebSocketHandshake.HttpHandshakeException wrongEx =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(serverConfig, wrongTokenRequest));
    assertEquals(401, wrongEx.status());

    AgentConfig outboundNullTokenConfig =
        new AgentConfig("ws://127.0.0.1:8765/ws/agent", null, null, null, null, "demo", null);
    WebSocketHandshake.HandshakeRequest literalNullHeaderRequest =
        new WebSocketHandshake.HandshakeRequest(
            "GET", "/ws/agent", Map.of(), upgradeHeaders("Bearer null"));

    WebSocketHandshake.HttpHandshakeException outboundEx =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () ->
                WebSocketHandshakeValidator.validate(
                    outboundNullTokenConfig, literalNullHeaderRequest));
    assertEquals(401, outboundEx.status());
  }

  @Test
  @DisplayName("Validator rejects query-string tokens with HTTP 400 before bearer check")
  void testValidatorRejectsQueryStringTokensWith400() {
    AgentConfig config =
        new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", CONFIGURED_TOKEN, "demo", null);
    WebSocketHandshake.HandshakeRequest queryTokenRequest =
        new WebSocketHandshake.HandshakeRequest(
            "GET",
            "/ws/agent",
            Map.of("token", CONFIGURED_TOKEN),
            upgradeHeaders("Bearer " + CONFIGURED_TOKEN));

    WebSocketHandshake.HttpHandshakeException ex =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, queryTokenRequest));
    assertEquals(400, ex.status());
    assertEquals("Bad Request", ex.reason());
  }

  @Test
  @DisplayName("Validator accepts matching Authorization: Bearer <token>")
  void testValidatorAcceptsMatchingBearerToken() {
    AgentConfig config =
        new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", CONFIGURED_TOKEN, "demo", null);
    WebSocketHandshake.HandshakeRequest validRequest =
        new WebSocketHandshake.HandshakeRequest(
            "GET", "/ws/agent", Map.of(), upgradeHeaders("Bearer " + CONFIGURED_TOKEN));

    assertDoesNotThrow(() -> WebSocketHandshakeValidator.validate(config, validRequest));
  }

  @Test
  @DisplayName("AgentWebSocketServer rejects outbound AgentConfig")
  void testServerRejectsOutboundConfig() {
    AgentConfig outbound =
        new AgentConfig("ws://127.0.0.1:8765/ws/agent", null, null, null, null, "demo", null);
    assertThrows(
        IllegalArgumentException.class,
        () -> new AgentWebSocketServer(outbound, new NoOpHandler(new CountDownLatch(1))));
  }

  @Test
  @DisplayName("Live AgentWebSocketServer on 127.0.0.1 returns 401 without bearer token, 403 for untrusted Origin, 400 for query token, and 101 with valid bearer token")
  void testLiveLoopbackServerUpgradeResponses() throws Exception {
    CountDownLatch openedLatch = new CountDownLatch(1);
    StartedServer started = startServerOnEphemeralPort(CONFIGURED_TOKEN, openedLatch);
    try (AgentWebSocketServer ignored = started.server()) {
      int port = started.port();

      // 1. Unauthenticated upgrade without Origin or from another local port must receive 401.
      List<String> unauthResponse = sendRawHttpUpgrade(port, "/ws/agent", "");
      assertEquals("HTTP/1.1 401 Unauthorized", unauthResponse.getFirst());
      assertTrue(unauthResponse.contains("WWW-Authenticate: Bearer"));

      List<String> localOriginUnauthResponse =
          sendRawHttpUpgrade(port, "/ws/agent", "Origin: http://localhost:3000\r\n");
      assertEquals("HTTP/1.1 401 Unauthorized", localOriginUnauthResponse.getFirst());
      assertTrue(localOriginUnauthResponse.contains("WWW-Authenticate: Bearer"));

      // 2. Untrusted cross-origin upgrade must receive HTTP/1.1 403 Forbidden even with token.
      List<String> crossOriginResponse =
          sendRawHttpUpgrade(
              port,
              "/ws/agent",
              "Origin: https://untrusted-origin.example\r\nAuthorization: Bearer "
                  + CONFIGURED_TOKEN
                  + "\r\n");
      assertEquals("HTTP/1.1 403 Forbidden", crossOriginResponse.getFirst());

      // 3. Query token upgrade must receive HTTP/1.1 400 Bad Request.
      List<String> queryTokenResponse =
          sendRawHttpUpgrade(port, "/ws/agent?token=" + CONFIGURED_TOKEN, "");
      assertEquals("HTTP/1.1 400 Bad Request", queryTokenResponse.getFirst());

      // 4. Authenticated upgrade with Authorization: Bearer <token> must receive HTTP/1.1 101.
      try (Socket authSocket = new Socket("127.0.0.1", port)) {
        authSocket.setSoTimeout(5_000);
        String request =
            "GET /ws/agent HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + port
                + "\r\n"
                + "Origin: http://127.0.0.1:"
                + port
                + "\r\n"
                + "Authorization: Bearer "
                + CONFIGURED_TOKEN
                + "\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Key: "
                + SAMPLE_WS_KEY
                + "\r\n"
                + "Sec-WebSocket-Version: 13\r\n\r\n";
        OutputStream out = authSocket.getOutputStream();
        out.write(request.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        List<String> authResponse = readHttpHeaderLines(authSocket);
        assertEquals("HTTP/1.1 101 Switching Protocols", authResponse.getFirst());
        assertTrue(authResponse.contains("Sec-WebSocket-Accept: " + SAMPLE_WS_ACCEPT));
        assertTrue(openedLatch.await(5, TimeUnit.SECONDS));
      }
    }
  }

  private static Map<String, String> upgradeHeaders(String authorization) {
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("host", "127.0.0.1:8765");
    headers.put("upgrade", "websocket");
    headers.put("connection", "Upgrade");
    headers.put("sec-websocket-key", SAMPLE_WS_KEY);
    headers.put("sec-websocket-version", "13");
    if (authorization != null) {
      headers.put("authorization", authorization);
    }
    return headers;
  }

  private static StartedServer startServerOnEphemeralPort(String token, CountDownLatch openedLatch)
      throws IOException {
    BindException lastBindError = null;
    for (int attempt = 0; attempt < 10; attempt++) {
      int port;
      try (ServerSocket probe = new ServerSocket(0)) {
        port = probe.getLocalPort();
      }
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", token, "demo", null);
      AgentWebSocketServer server =
          new AgentWebSocketServer(config, new NoOpHandler(openedLatch));
      try {
        server.start();
        return new StartedServer(server, port);
      } catch (BindException bindError) {
        lastBindError = bindError;
      }
    }
    throw new IOException("Unable to bind test server on ephemeral port", lastBindError);
  }

  private static List<String> sendRawHttpUpgrade(int port, String target, String extraHeaders)
      throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5_000);
      String request =
          "GET "
              + target
              + " HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + extraHeaders
              + "Upgrade: websocket\r\n"
              + "Connection: Upgrade\r\n"
              + "Sec-WebSocket-Key: "
              + SAMPLE_WS_KEY
              + "\r\n"
              + "Sec-WebSocket-Version: 13\r\n\r\n";
      OutputStream out = socket.getOutputStream();
      out.write(request.getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return readHttpHeaderLines(socket);
    }
  }

  private static List<String> readHttpHeaderLines(Socket socket) throws IOException {
    BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
    List<String> lines = new ArrayList<>();
    String line;
    while ((line = reader.readLine()) != null && !line.isEmpty()) {
      lines.add(line);
    }
    return lines;
  }

  private record StartedServer(AgentWebSocketServer server, int port) {}

  private static final class NoOpHandler implements AgentWebSocketServer.Handler {
    private final CountDownLatch openedLatch;

    private NoOpHandler(CountDownLatch openedLatch) {
      this.openedLatch = openedLatch;
    }

    @Override
    public void onOpen(AgentWebSocketServer.Connection connection) {
      openedLatch.countDown();
    }

    @Override
    public void onText(AgentWebSocketServer.Connection connection, String message) {}

    @Override
    public void onClose(
        AgentWebSocketServer.Connection connection, int statusCode, String reason) {}

    @Override
    public void onConnectionError(
        AgentWebSocketServer.Connection connection, Throwable error) {}

    @Override
    public void onServerError(Throwable error) {}
  }
}
