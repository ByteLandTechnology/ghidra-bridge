package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WebSocketOriginValidationTest {
  private static final String SAMPLE_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
  private static final String LOOPBACK_TOKEN = "loopback-secret-token";
  private static final String LOOPBACK_AUTH_HEADER = "Authorization: Bearer " + LOOPBACK_TOKEN;

  @Test
  @DisplayName("Permits upgrade requests that omit the Origin header")
  void allowsAbsentOriginHeader() throws IOException {
    AgentConfig config = loopbackConfig("127.0.0.1", 8765);
    WebSocketHandshake.HandshakeRequest request =
        readHandshake(rawUpgradeRequest("127.0.0.1:8765", List.of(LOOPBACK_AUTH_HEADER)));

    assertDoesNotThrow(() -> WebSocketHandshakeValidator.validate(config, request));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://127.0.0.1:8765",
        "http://127.0.0.2:8765",
        "http://127.255.255.254:9000",
        "http://localhost:3000",
        "http://[::1]:8765",
        "http://[0:0:0:0:0:0:0:1]:8765",
        "http://[::ffff:127.0.0.1]:8765",
        "http://[::ffff:127.0.0.2]:8765",
        "https://localhost",
        "https://LOCALHOST:8443",
        "https://[::1]"
      })
  @DisplayName("Permits literal loopback Origin headers on loopback listeners")
  void allowsLoopbackOriginsOnLoopbackListeners(String origin) throws IOException {
    for (String bindHost : List.of("127.0.0.1", "127.0.0.2", "localhost", "::1")) {
      AgentConfig config = loopbackConfig(bindHost, 8765);
      WebSocketHandshake.HandshakeRequest request =
          readHandshake(
              rawUpgradeRequest(
                  "127.0.0.1:8765", List.of("Origin: " + origin, LOOPBACK_AUTH_HEADER)));

      assertDoesNotThrow(
          () -> WebSocketHandshakeValidator.validate(config, request),
          "Expected allowed origin " + origin + " on listener " + bindHost);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https://untrusted-origin.example",
        "http://untrusted-origin.example:8080",
        "http://127.0.0.1.untrusted.example",
        "http://evil-localhost",
        "http://sub.localhost:3000",
        "http://0.0.0.0:8765",
        "http://[::]:8765",
        "http://[fe80::1]:8765",
        "http://192.0.2.10:8765",
        "http://127.0.0.01:8765",
        "http://127.1:8765",
        "http://2130706433:8765",
        "http://[::1%25lo0]:8765",
        "null",
        "NULL",
        "",
        "   ",
        "not a valid uri",
        "http://",
        "http://bad_host:8765",
        "ws://127.0.0.1:8765",
        "wss://localhost:8765",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "http:127.0.0.1",
        "http://127.0.0.1:8765/",
        "http://127.0.0.1:8765/ws/agent",
        "http://127.0.0.1:8765?foo=bar",
        "http://127.0.0.1:8765?",
        "http://127.0.0.1:8765#frag",
        "http://127.0.0.1:8765#",
        "http://user:pass@127.0.0.1:8765",
        "http://@127.0.0.1:8765",
        "http://127.0.0.1:",
        "http://[::1]:",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "https://untrusted-origin.example, http://127.0.0.1:8765"
      })
  @DisplayName("Rejects cross-origin, null, blank, non-HTTP, and malformed Origin headers with 403")
  void rejectsDisallowedAndMalformedOriginsWith403(String origin) throws IOException {
    AgentConfig config = loopbackConfig("127.0.0.1", 8765);
    WebSocketHandshake.HandshakeRequest request =
        readHandshake(rawUpgradeRequest("127.0.0.1:8765", List.of("Origin: " + origin)));

    WebSocketHandshake.HttpHandshakeException error =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, request));
    assertEquals(403, error.status());
    assertEquals("Forbidden", error.reason());
  }

  @Test
  @DisplayName("Rejects duplicate Origin headers instead of overwriting earlier values")
  void rejectsDuplicateOriginHeaders() {
    String evilThenAllowed =
        rawUpgradeRequest(
            "127.0.0.1:8765",
            List.of("Origin: https://untrusted-origin.example", "Origin: http://127.0.0.1:8765"));
    WebSocketHandshake.HttpHandshakeException firstError =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> readHandshake(evilThenAllowed));
    assertEquals(403, firstError.status());
    assertEquals("Forbidden", firstError.reason());

    String mixedCaseDuplicate =
        rawUpgradeRequest(
            "127.0.0.1:8765",
            List.of("Origin: http://127.0.0.1:8765", "origin: http://127.0.0.1:8765"));
    WebSocketHandshake.HttpHandshakeException secondError =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> readHandshake(mixedCaseDuplicate));
    assertEquals(403, secondError.status());
    assertEquals("Forbidden", secondError.reason());

    AgentConfig config = loopbackConfig("127.0.0.1", 8765);
    Map<String, String> headers = baseHeaders();
    headers.put("origin", "http://127.0.0.1:8765");
    WebSocketHandshake.HandshakeRequest directDuplicate =
        new WebSocketHandshake.HandshakeRequest(
            "GET",
            "/ws/agent",
            Map.of(),
            headers,
            List.of("https://untrusted-origin.example", "http://127.0.0.1:8765"));
    WebSocketHandshake.HttpHandshakeException validatorError =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(config, directDuplicate));
    assertEquals(403, validatorError.status());
    assertEquals("Forbidden", validatorError.reason());
  }

  @Test
  @DisplayName("Enforces exact configured host match on non-loopback listeners")
  void enforcesConfiguredHostOnNonLoopbackListeners() throws IOException {
    AgentConfig ipv4Config =
        new AgentConfig(null, "192.0.2.10", 8765, "/ws/agent", "secret-token", "demo", null);

    WebSocketHandshake.HandshakeRequest matchingOrigin =
        readHandshake(
            rawUpgradeRequest(
                "192.0.2.10:8765",
                List.of(
                    "Origin: https://192.0.2.10:8443", "Authorization: Bearer secret-token")));
    assertDoesNotThrow(() -> WebSocketHandshakeValidator.validate(ipv4Config, matchingOrigin));

    for (String disallowed :
        List.of(
            "http://127.0.0.1:8765",
            "http://127.0.0.2:8765",
            "http://localhost:3000",
            "http://[::1]:8765",
            "https://untrusted-origin.example")) {
      WebSocketHandshake.HandshakeRequest withToken =
          readHandshake(
              rawUpgradeRequest(
                  "192.0.2.10:8765",
                  List.of("Origin: " + disallowed, "Authorization: Bearer secret-token")));
      WebSocketHandshake.HttpHandshakeException errorWithToken =
          assertThrows(
              WebSocketHandshake.HttpHandshakeException.class,
              () -> WebSocketHandshakeValidator.validate(ipv4Config, withToken));
      assertEquals(403, errorWithToken.status());
      assertEquals("Forbidden", errorWithToken.reason());

      WebSocketHandshake.HandshakeRequest withoutToken =
          readHandshake(
              rawUpgradeRequest("192.0.2.10:8765", List.of("Origin: " + disallowed)));
      WebSocketHandshake.HttpHandshakeException errorWithoutToken =
          assertThrows(
              WebSocketHandshake.HttpHandshakeException.class,
              () -> WebSocketHandshakeValidator.validate(ipv4Config, withoutToken));
      assertEquals(403, errorWithoutToken.status());
      assertEquals("Forbidden", errorWithoutToken.reason());
    }

    AgentConfig ipv6Config =
        new AgentConfig(null, "2001:db8::1", 8765, "/ws/agent", "secret-token", "demo", null);
    WebSocketHandshake.HandshakeRequest matchingIpv6Origin =
        readHandshake(
            rawUpgradeRequest(
                "[2001:db8::1]:8765",
                List.of(
                    "Origin: https://[2001:DB8::1]:8443", "Authorization: Bearer secret-token")));
    assertDoesNotThrow(() -> WebSocketHandshakeValidator.validate(ipv6Config, matchingIpv6Origin));

    WebSocketHandshake.HandshakeRequest expandedIpv6Origin =
        readHandshake(
            rawUpgradeRequest(
                "[2001:db8::1]:8765",
                List.of(
                    "Origin: https://[2001:0db8:0:0:0:0:0:1]:8443",
                    "Authorization: Bearer secret-token")));
    assertDoesNotThrow(() -> WebSocketHandshakeValidator.validate(ipv6Config, expandedIpv6Origin));

    AgentConfig wildcardConfig =
        new AgentConfig(null, "0.0.0.0", 8765, "/ws/agent", "secret-token", "demo", null);
    WebSocketHandshake.HandshakeRequest wildcardOrigin =
        readHandshake(
            rawUpgradeRequest(
                "192.0.2.10:8765",
                List.of("Origin: http://0.0.0.0:8765", "Authorization: Bearer secret-token")));
    WebSocketHandshake.HttpHandshakeException wildcardError =
        assertThrows(
            WebSocketHandshake.HttpHandshakeException.class,
            () -> WebSocketHandshakeValidator.validate(wildcardConfig, wildcardOrigin));
    assertEquals(403, wildcardError.status());
  }

  @Test
  @DisplayName("Server returns 403 for untrusted Origin, releases client slot, and upgrades valid clients with 101")
  void serverRejectsUntrustedOriginAndReleasesClientSlot() throws Exception {
    AtomicInteger openCount = new AtomicInteger();
    RecordingHandler handler = new RecordingHandler(openCount);

    try (StartedServer started = startLoopbackServer(handler)) {
      int port = started.port();

      // 1. Exact untrusted browser upgrade probe returns HTTP/1.1 403 Forbidden.
      String untrustedUpgrade =
          "GET /ws/agent HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Origin: https://untrusted-origin.example\r\n"
              + "Upgrade: websocket\r\n"
              + "Connection: Upgrade\r\n"
              + "Sec-WebSocket-Key: "
              + SAMPLE_KEY
              + "\r\n"
              + "Sec-WebSocket-Version: 13\r\n\r\n";
      String untrustedResponse = sendRawAndReadHttpResponse(port, untrustedUpgrade);
      assertTrue(
          untrustedResponse.startsWith("HTTP/1.1 403 Forbidden\r\n"),
          () -> "Expected 403 Forbidden but got: " + untrustedResponse);
      assertEquals(0, openCount.get(), "Rejected upgrade must not open a session");

      // 2. Origin: null and duplicate Origin headers also return HTTP/1.1 403 Forbidden without wedging the slot.
      String nullOriginResponse =
          sendRawAndReadHttpResponse(
              port, rawUpgradeRequest("127.0.0.1:" + port, List.of("Origin: null")));
      assertTrue(
          nullOriginResponse.startsWith("HTTP/1.1 403 Forbidden\r\n"),
          () -> "Expected 403 Forbidden for Origin: null but got: " + nullOriginResponse);

      String duplicateOriginResponse =
          sendRawAndReadHttpResponse(
              port,
              rawUpgradeRequest(
                  "127.0.0.1:" + port,
                  List.of(
                      "Origin: https://untrusted-origin.example",
                      "Origin: http://127.0.0.1:" + port)));
      assertTrue(
          duplicateOriginResponse.startsWith("HTTP/1.1 403 Forbidden\r\n"),
          () -> "Expected 403 Forbidden for duplicate Origin but got: " + duplicateOriginResponse);
      assertEquals(0, openCount.get());

      // 3. Immediately following 403 rejections, allowed loopback Origin upgrades succeed with 101 (not 409).
      assertSuccessfulUpgradeAndClose(
          port,
          rawUpgradeRequest(
              "127.0.0.1:" + port,
              List.of("Origin: http://127.0.0.1:" + port, LOOPBACK_AUTH_HEADER)),
          handler);
      assertEquals(1, openCount.get());

      // 4. Absent Origin header continues to succeed with 101 Switching Protocols.
      assertSuccessfulUpgradeAndClose(
          port, rawUpgradeRequest("127.0.0.1:" + port, List.of(LOOPBACK_AUTH_HEADER)), handler);
      assertEquals(2, openCount.get());

      // 5. 127.0.0.2, localhost, and [::1] Origin headers also succeed with 101 Switching Protocols.
      assertSuccessfulUpgradeAndClose(
          port,
          rawUpgradeRequest(
              "127.0.0.1:" + port,
              List.of("Origin: http://127.0.0.2:" + port, LOOPBACK_AUTH_HEADER)),
          handler);
      assertSuccessfulUpgradeAndClose(
          port,
          rawUpgradeRequest(
              "127.0.0.1:" + port, List.of("Origin: http://localhost:3000", LOOPBACK_AUTH_HEADER)),
          handler);
      assertSuccessfulUpgradeAndClose(
          port,
          rawUpgradeRequest(
              "127.0.0.1:" + port, List.of("Origin: http://[::1]:" + port, LOOPBACK_AUTH_HEADER)),
          handler);
      assertEquals(5, openCount.get());
    }
  }

  private static void assertSuccessfulUpgradeAndClose(
      int port, String request, RecordingHandler handler) throws Exception {
    CountDownLatch closeLatch = handler.resetCloseLatch();
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5_000);
      OutputStream output = socket.getOutputStream();
      output.write(request.getBytes(StandardCharsets.US_ASCII));
      output.flush();

      String responseHeaders = readHttpHeaders(socket.getInputStream());
      assertTrue(
          responseHeaders.startsWith("HTTP/1.1 101 Switching Protocols\r\n"),
          () -> "Expected 101 Switching Protocols but got: " + responseHeaders);
    }
    assertTrue(
        closeLatch.await(5, TimeUnit.SECONDS),
        "Expected server connection to close and release slot");
  }

  private static String sendRawAndReadHttpResponse(int port, String rawRequest) throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5_000);
      OutputStream output = socket.getOutputStream();
      output.write(rawRequest.getBytes(StandardCharsets.US_ASCII));
      output.flush();
      return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static String readHttpHeaders(InputStream input) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int matched = 0;
    while (matched < 4) {
      int b = input.read();
      if (b < 0) {
        break;
      }
      buffer.write(b);
      matched =
          switch (matched) {
            case 0 -> b == '\r' ? 1 : 0;
            case 1 -> b == '\n' ? 2 : 0;
            case 2 -> b == '\r' ? 3 : 0;
            case 3 -> b == '\n' ? 4 : 0;
            default -> matched;
          };
    }
    return buffer.toString(StandardCharsets.US_ASCII);
  }

  private static StartedServer startLoopbackServer(AgentWebSocketServer.Handler handler)
      throws IOException {
    IOException lastBindFailure = null;
    for (int attempt = 0; attempt < 10; attempt++) {
      int candidatePort;
      try (ServerSocket probe = new ServerSocket(0)) {
        candidatePort = probe.getLocalPort();
      }
      AgentConfig config = loopbackConfig("127.0.0.1", candidatePort);
      AgentWebSocketServer server = new AgentWebSocketServer(config, handler);
      try {
        server.start();
        return new StartedServer(server, candidatePort);
      } catch (BindException bindFailure) {
        lastBindFailure = bindFailure;
      }
    }
    throw new IOException("Unable to bind test server after retries", lastBindFailure);
  }

  private static AgentConfig loopbackConfig(String host, int port) {
    return new AgentConfig(null, host, port, "/ws/agent", LOOPBACK_TOKEN, "test-session", null);
  }

  private static WebSocketHandshake.HandshakeRequest readHandshake(String rawRequest)
      throws IOException {
    ByteArrayInputStream input =
        new ByteArrayInputStream(rawRequest.getBytes(StandardCharsets.US_ASCII));
    Socket socket =
        new Socket() {
          @Override
          public InputStream getInputStream() {
            return input;
          }

          @Override
          public void setSoTimeout(int timeout) {}
        };
    return WebSocketHandshake.readHandshake(
        socket, System.nanoTime() + TimeUnit.SECONDS.toNanos(5));
  }

  private static String rawUpgradeRequest(String hostHeader, List<String> extraHeaders) {
    StringBuilder builder = new StringBuilder();
    builder
        .append("GET /ws/agent HTTP/1.1\r\n")
        .append("Host: ")
        .append(hostHeader)
        .append("\r\n")
        .append("Upgrade: websocket\r\n")
        .append("Connection: Upgrade\r\n")
        .append("Sec-WebSocket-Key: ")
        .append(SAMPLE_KEY)
        .append("\r\n")
        .append("Sec-WebSocket-Version: 13\r\n");
    for (String header : extraHeaders) {
      builder.append(header).append("\r\n");
    }
    builder.append("\r\n");
    return builder.toString();
  }

  private static Map<String, String> baseHeaders() {
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("host", "127.0.0.1:8765");
    headers.put("upgrade", "websocket");
    headers.put("connection", "Upgrade");
    headers.put("sec-websocket-key", SAMPLE_KEY);
    headers.put("sec-websocket-version", "13");
    return headers;
  }

  private record StartedServer(AgentWebSocketServer server, int port) implements AutoCloseable {
    @Override
    public void close() {
      server.close();
    }
  }

  private static final class RecordingHandler implements AgentWebSocketServer.Handler {
    private final AtomicInteger openCount;
    private volatile CountDownLatch closeLatch = new CountDownLatch(1);

    private RecordingHandler(AtomicInteger openCount) {
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
    public void onClose(
        AgentWebSocketServer.Connection connection, int statusCode, String reason) {
      closeLatch.countDown();
    }

    @Override
    public void onConnectionError(AgentWebSocketServer.Connection connection, Throwable error) {}

    @Override
    public void onServerError(Throwable error) {}
  }
}
