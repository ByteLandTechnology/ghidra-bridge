package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class WebSocketHostValidationTest {
  private static final String LOOPBACK_TOKEN = "loopback-secret-token";

  @Test
  @DisplayName("readHandshake rejects missing, blank, malformed, and duplicate Host headers with 400")
  void readHandshakeRejectsInvalidHostHeaders() {
    List<String> invalidHandshakes =
        List.of(
            "GET /ws/agent HTTP/1.1\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n\r\n",
            "GET /ws/agent HTTP/1.1\r\n"
                + "Host:   \r\n"
                + "Upgrade: websocket\r\n\r\n",
            "GET /ws/agent HTTP/1.1\r\n"
                + "Host: [::1\r\n"
                + "Upgrade: websocket\r\n\r\n",
            "GET /ws/agent HTTP/1.1\r\n"
                + "Host: 127.0.0.1:8765\r\n"
                + "Host: rebind.example.invalid:8765\r\n"
                + "Upgrade: websocket\r\n\r\n",
            "GET /ws/agent HTTP/1.1\r\n"
                + "Host : 127.0.0.1:8765\r\n"
                + "Upgrade: websocket\r\n\r\n");

    for (String raw : invalidHandshakes) {
      WebSocketHandshake.HttpHandshakeException ex =
          assertThrows(
              WebSocketHandshake.HttpHandshakeException.class,
              () ->
                  WebSocketHandshake.readHandshake(
                      new ByteArrayInputStream(raw.getBytes(StandardCharsets.US_ASCII))));
      assertEquals(400, ex.status());
    }
  }

  @Test
  @DisplayName("WebSocketHandshakeValidator rejects external Host with 403 and missing/duplicate Host with 400")
  void validatorEnforcesHostRulesBeforeUpgrade() {
    AgentConfig config =
        new AgentConfig(
            null, "127.0.0.1", 8765, "/ws/agent", LOOPBACK_TOKEN, "session-1", null);

    WebSocketHandshake.HandshakeRequest externalHost =
        new WebSocketHandshake.HandshakeRequest(
            "GET",
            "/ws/agent",
            Map.of(),
            Map.of(
                "host", "rebind.example.invalid:8765",
                "upgrade", "websocket",
                "connection", "Upgrade",
                "sec-websocket-version", "13"));
    WebSocketHandshake.HttpHandshakeException forbidden =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, externalHost));
    assertEquals(403, forbidden.status());

    WebSocketHandshake.HandshakeRequest missingHost =
        new WebSocketHandshake.HandshakeRequest(
            "GET",
            "/ws/agent",
            Map.of(),
            Map.of(
                "upgrade", "websocket",
                "connection", "Upgrade",
                "sec-websocket-version", "13",
                "sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="));
    WebSocketHandshake.HttpHandshakeException badMissing =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, missingHost));
    assertEquals(400, badMissing.status());

    WebSocketHandshake.HandshakeRequest duplicateHost =
        new WebSocketHandshake.HandshakeRequest(
            "GET",
            "/ws/agent",
            Map.of(),
            Map.of(
                "host", "127.0.0.1:8765",
                "upgrade", "websocket",
                "connection", "Upgrade",
                "sec-websocket-version", "13",
                "sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            List.of("127.0.0.1:8765", "rebind.example.invalid:8765"),
            List.of());
    WebSocketHandshake.HttpHandshakeException badDuplicate =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, duplicateHost));
    assertEquals(400, badDuplicate.status());
  }

  @Test
  @DisplayName("AgentWebSocketServer rejects DNS rebinding probes (403) and missing/duplicate Host (400), while allowing loopback Hosts (101)")
  void serverEnforcesHostRulesOverLiveSockets() throws Exception {
    AtomicInteger openCount = new AtomicInteger();
    try (RunningWsServer running = startWsServer("127.0.0.1", LOOPBACK_TOKEN, openCount)) {
      int port = running.port();

      // Exact WebSocket probe from proof harness (without Sec-WebSocket-Key)
      int rebindStatus =
          sendWsHandshakeStatus(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n\r\n");
      assertEquals(403, rebindStatus);

      // WebSocket upgrade with Sec-WebSocket-Key and external Host
      int rebindFullStatus =
          sendWsHandshakeStatus(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(403, rebindFullStatus);

      // Absent Host -> 400
      int missingStatus =
          sendWsHandshakeStatus(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(400, missingStatus);

      // Duplicate Host -> 400
      int duplicateStatus =
          sendWsHandshakeStatus(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(400, duplicateStatus);
      assertEquals(0, openCount.get());

      // Valid loopback Host headers return `101 Switching Protocols`.
      for (String allowedHost :
          List.of("127.0.0.1:" + port, "[::1]:" + port, "localhost:" + port)) {
        CountDownLatch closedLatch = running.resetCloseLatch();
        int upgradeStatus =
            sendWsHandshakeStatus(
                port,
                "GET /ws/agent HTTP/1.1\r\n"
                    + "Host: "
                    + allowedHost
                    + "\r\n"
                    + "Authorization: Bearer "
                    + LOOPBACK_TOKEN
                    + "\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
        assertEquals(101, upgradeStatus, "Expected 101 upgrade for Host: " + allowedHost);
        assertTrue(closedLatch.await(5, TimeUnit.SECONDS));
      }
      assertEquals(3, openCount.get());
    }
  }

  @Test
  @DisplayName("Authenticated non-loopback AgentWebSocketServer enforces well-formed Host and bearer token")
  void authenticatedNonLoopbackServerEnforcesHostAndToken() throws Exception {
    AtomicInteger openCount = new AtomicInteger();
    try (RunningWsServer running = startWsServer("0.0.0.0", "ws-secret-token", openCount)) {
      int port = running.port();

      // Absent token -> 401
      int unauthorized =
          sendWsHandshakeStatus(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: bridge.corp.example:8443\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(401, unauthorized);

      // Valid token + single well-formed Host -> 101
      CountDownLatch closedLatch = running.resetCloseLatch();
      int upgraded =
          sendWsHandshakeStatus(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: bridge.corp.example:8443\r\n"
                  + "Authorization: Bearer ws-secret-token\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(101, upgraded);
      assertTrue(closedLatch.await(5, TimeUnit.SECONDS));
      assertEquals(1, openCount.get());
    }
  }

  private static int sendWsHandshakeStatus(int port, String rawHandshake)
      throws IOException, InterruptedException {
    for (int attempt = 0; attempt < 20; attempt++) {
      try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
        socket.setSoTimeout(5_000);
        OutputStream out = socket.getOutputStream();
        out.write(rawHandshake.getBytes(StandardCharsets.US_ASCII));
        out.flush();
        BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        String statusLine = reader.readLine();
        if (statusLine == null) {
          throw new IOException("Empty handshake response");
        }
        int status = Integer.parseInt(statusLine.split(" ", 3)[1]);
        if (status == 409 && attempt < 19) {
          // Retry briefly if cleanup of the previous rejected socket slot races on the worker thread.
          Thread.sleep(25L);
          continue;
        }
        return status;
      }
    }
    throw new IOException("Unexpected busy responses");
  }

  private static RunningWsServer startWsServer(String host, String token, AtomicInteger openCount)
      throws IOException {
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = findFreePort();
      AgentConfig config =
          new AgentConfig(null, host, port, "/ws/agent", token, "test-session", null);
      TestWsHandler handler = new TestWsHandler(openCount);
      AgentWebSocketServer server = new AgentWebSocketServer(config, handler);
      try {
        server.start();
        return new RunningWsServer(server, handler, port);
      } catch (BindException retry) {
        server.close();
      }
    }
    throw new IOException("Unable to bind AgentWebSocketServer after retries");
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      return socket.getLocalPort();
    }
  }

  private static final class TestWsHandler implements AgentWebSocketServer.Handler {
    private final AtomicInteger openCount;
    private volatile CountDownLatch closeLatch = new CountDownLatch(1);

    TestWsHandler(AtomicInteger openCount) {
      this.openCount = openCount;
    }

    CountDownLatch resetCloseLatch() {
      CountDownLatch latch = new CountDownLatch(1);
      this.closeLatch = latch;
      return latch;
    }

    @Override
    public void onOpen(AgentWebSocketServer.Connection connection) {
      openCount.incrementAndGet();
    }

    @Override
    public void onText(AgentWebSocketServer.Connection connection, String message) {}

    @Override
    public void onClose(AgentWebSocketServer.Connection connection, int statusCode, String reason) {
      closeLatch.countDown();
    }

    @Override
    public void onConnectionError(AgentWebSocketServer.Connection connection, Throwable error) {}

    @Override
    public void onServerError(Throwable error) {}
  }

  private record RunningWsServer(
      AgentWebSocketServer server, TestWsHandler handler, int port) implements AutoCloseable {
    CountDownLatch resetCloseLatch() {
      return handler.resetCloseLatch();
    }

    @Override
    public void close() {
      server.close();
    }
  }
}
