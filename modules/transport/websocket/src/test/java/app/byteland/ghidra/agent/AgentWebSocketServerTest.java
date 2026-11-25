package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentWebSocketServerTest {
  private static final String TOKEN = "secret-test-token";
  private static final String VALID_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ==";

  @Test
  @DisplayName(
      "Bearer-authenticated client receives 101 while unauthenticated socket trickles header bytes")
  void testBearerClientReceives101WhileUnauthenticatedSocketTrickles() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startDefaultServer(TOKEN, handler);
        HttpClient httpClient = HttpClient.newHttpClient()) {
      int port = started.port();
      String token = TOKEN;
      TestWebSocketListener listener = new TestWebSocketListener();

      try (Socket unauthPartial = new Socket("127.0.0.1", port)) {
        OutputStream unauthOut = unauthPartial.getOutputStream();
        unauthOut.write(
            ("GET /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nX-Marker: ")
                .getBytes(StandardCharsets.US_ASCII));
        unauthOut.flush();
        for (int i = 0; i < 3; i++) {
          Thread.sleep(3_000L);
          unauthOut.write('x');
          unauthOut.flush();
        }
        // Valid Bearer-authenticated client must receive `HTTP/1.1 101 Switching Protocols`, not
        // 409 Conflict.
        WebSocket ws =
            httpClient
                .newWebSocketBuilder()
                .header("Authorization", "Bearer " + token)
                .buildAsync(URI.create("ws://127.0.0.1:" + port + "/ws/agent"), listener)
                .get(5, TimeUnit.SECONDS);
        assertNotNull(ws);
        assertTrue(listener.openLatch.await(5, TimeUnit.SECONDS));

        ws.sendText("ping-check", true).get(5, TimeUnit.SECONDS);
        assertEquals("echo:ping-check", listener.messages.poll(5, TimeUnit.SECONDS));
        ws.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(5, TimeUnit.SECONDS);
      }
    }
  }

  @Test
  @DisplayName("Trickling handshake bytes past total deadline returns HTTP 408 Request Timeout")
  void testTricklingHandshakeExceedingTotalDeadlineReturns408() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startCustomServer(TOKEN, handler, Duration.ofMillis(300), 8)) {
      try (Socket trickle = new Socket("127.0.0.1", started.port())) {
        trickle.setSoTimeout(3_000);
        OutputStream out = trickle.getOutputStream();
        out.write(
            ("GET /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:" + started.port() + "\r\nX-Slow: ")
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        for (int i = 0; i < 5; i++) {
          Thread.sleep(80L);
          try {
            out.write('a');
            out.flush();
          } catch (IOException ignored) {
            break;
          }
        }
        String response = readAllAscii(trickle.getInputStream());
        assertTrue(
            response.startsWith("HTTP/1.1 408 Request Timeout\r\n"),
            () -> "Expected HTTP 408 response, got: " + response);
      }
    }
  }

  @Test
  @DisplayName("Idle handshake exceeding total deadline returns HTTP 408 Request Timeout")
  void testIdleHandshakeExceedingTotalDeadlineReturns408() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startCustomServer(TOKEN, handler, Duration.ofMillis(200), 8)) {
      try (Socket idle = new Socket("127.0.0.1", started.port())) {
        idle.setSoTimeout(3_000);
        OutputStream out = idle.getOutputStream();
        out.write("GET /ws/agent HTTP/1.1\r\n".getBytes(StandardCharsets.US_ASCII));
        out.flush();

        String response = readAllAscii(idle.getInputStream());
        assertTrue(
            response.startsWith("HTTP/1.1 408 Request Timeout\r\n"),
            () -> "Expected HTTP 408 response, got: " + response);
      }
    }
  }

  @Test
  @DisplayName("Writes HTTP 401, 400, 404, and 405 responses before closing the socket")
  void testWritesHandshakeValidationErrorsBeforeClosingSocket() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startDefaultServer(TOKEN, handler)) {
      int port = started.port();

      String unauthorized =
          sendRawRequest(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: "
                  + VALID_WS_KEY
                  + "\r\n\r\n");
      assertTrue(
          unauthorized.startsWith("HTTP/1.1 401 Unauthorized\r\n"),
          () -> "Expected 401 response, got: " + unauthorized);

      String wrongMethod =
          sendRawRequest(port, "POST /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n");
      assertTrue(
          wrongMethod.startsWith("HTTP/1.1 405 Method Not Allowed\r\n"),
          () -> "Expected 405 response, got: " + wrongMethod);

      String wrongPath =
          sendRawRequest(port, "GET /other HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n");
      assertTrue(
          wrongPath.startsWith("HTTP/1.1 404 Not Found\r\n"),
          () -> "Expected 404 response, got: " + wrongPath);

      String missingUpgrade =
          sendRawRequest(port, "GET /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n");
      assertTrue(
          missingUpgrade.startsWith("HTTP/1.1 400 Bad Request\r\n"),
          () -> "Expected 400 response, got: " + missingUpgrade);
    }
  }

  @Test
  @DisplayName(
      "Preserves single-client exclusivity with 409 for authenticated second client and 401 for"
          + " unauthenticated")
  void testSingleClientExclusivityAndRecoveryAfterDisconnect() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startDefaultServer(TOKEN, handler);
        HttpClient httpClient = HttpClient.newHttpClient()) {
      int port = started.port();
      URI uri = URI.create("ws://127.0.0.1:" + port + "/ws/agent");

      TestWebSocketListener firstListener = new TestWebSocketListener();
      WebSocket first =
          httpClient
              .newWebSocketBuilder()
              .header("Authorization", "Bearer " + TOKEN)
              .buildAsync(uri, firstListener)
              .get(5, TimeUnit.SECONDS);
      assertTrue(firstListener.openLatch.await(5, TimeUnit.SECONDS));

      // Unauthenticated client while session is active still receives 401, not 409.
      ExecutionException unauthFailure =
          assertThrows(
              ExecutionException.class,
              () ->
                  httpClient
                      .newWebSocketBuilder()
                      .buildAsync(uri, new TestWebSocketListener())
                      .get(5, TimeUnit.SECONDS));
      WebSocketHandshakeException unauthHandshake =
          assertInstanceOf(WebSocketHandshakeException.class, unauthFailure.getCause());
      assertEquals(401, unauthHandshake.getResponse().statusCode());

      // Second authenticated client receives 409 Conflict while first client is active.
      ExecutionException secondFailure =
          assertThrows(
              ExecutionException.class,
              () ->
                  httpClient
                      .newWebSocketBuilder()
                      .header("Authorization", "Bearer " + TOKEN)
                      .buildAsync(uri, new TestWebSocketListener())
                      .get(5, TimeUnit.SECONDS));
      WebSocketHandshakeException conflictHandshake =
          assertInstanceOf(WebSocketHandshakeException.class, secondFailure.getCause());
      assertEquals(409, conflictHandshake.getResponse().statusCode());

      // First session remains unaffected and handler.onClose was not triggered by rejected clients.
      assertEquals(0, handler.closeCount.get());
      first.sendText("still-open", true).get(5, TimeUnit.SECONDS);
      assertEquals("echo:still-open", firstListener.messages.poll(5, TimeUnit.SECONDS));

      first.sendClose(WebSocket.NORMAL_CLOSURE, "bye").get(5, TimeUnit.SECONDS);
      assertTrue(handler.firstCloseLatch.await(5, TimeUnit.SECONDS));

      // After first session closes, another authenticated client can connect.
      TestWebSocketListener thirdListener = new TestWebSocketListener();
      WebSocket third =
          httpClient
              .newWebSocketBuilder()
              .header("Authorization", "Bearer " + TOKEN)
              .buildAsync(uri, thirdListener)
              .get(5, TimeUnit.SECONDS);
      assertTrue(thirdListener.openLatch.await(5, TimeUnit.SECONDS));
      third.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(5, TimeUnit.SECONDS);
    }
  }

  @Test
  @DisplayName(
      "Concurrent authenticated handshakes elect one 101 winner and return 409 to all losers")
  void testConcurrentAuthenticatedClientsRaceCleanly() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    int contenders = 6;
    try (StartedServer started =
        startCustomServer(TOKEN, handler, Duration.ofSeconds(5), contenders + 2)) {
      int port = started.port();
      CyclicBarrier barrier = new CyclicBarrier(contenders);
      ExecutorService pool = Executors.newFixedThreadPool(contenders);
      List<Socket> sockets = new CopyOnWriteArrayList<>();
      try {
        List<Future<Integer>> results = new ArrayList<>();
        for (int i = 0; i < contenders; i++) {
          results.add(
              pool.submit(() -> {
                Socket socket = new Socket("127.0.0.1", port);
                sockets.add(socket);
                socket.setSoTimeout(5_000);
                OutputStream out = socket.getOutputStream();
                String prefix =
                    "GET /ws/agent HTTP/1.1\r\n"
                        + "Host: 127.0.0.1:"
                        + port
                        + "\r\n"
                        + "Upgrade: websocket\r\n"
                        + "Connection: Upgrade\r\n"
                        + "Sec-WebSocket-Version: 13\r\n"
                        + "Sec-WebSocket-Key: "
                        + VALID_WS_KEY
                        + "\r\n"
                        + "Authorization: Bearer "
                        + TOKEN
                        + "\r\n";
                out.write(prefix.getBytes(StandardCharsets.US_ASCII));
                out.flush();
                barrier.await(5, TimeUnit.SECONDS);
                out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
                out.flush();
                return readStatusCode(socket.getInputStream());
              }));
        }

        int winners = 0;
        int conflicts = 0;
        for (Future<Integer> future : results) {
          int status = future.get(5, TimeUnit.SECONDS);
          if (status == 101) {
            winners++;
          } else if (status == 409) {
            conflicts++;
          }
        }
        assertEquals(1, winners);
        assertEquals(contenders - 1, conflicts);
      } finally {
        for (Socket socket : sockets) {
          socket.close();
        }
        pool.shutdownNow();
      }
    }
  }

  @Test
  @DisplayName("Bounds concurrent pending sockets and recovers once a pending slot frees")
  void testBoundedPendingSocketsRejectsExcessAndRecovers() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startCustomServer(TOKEN, handler, Duration.ofSeconds(5), 2);
        HttpClient httpClient = HttpClient.newHttpClient()) {
      int port = started.port();

      try (Socket pending2 = openPartialHandshake(port)) {
        try (Socket pending1 = openPartialHandshake(port)) {
          assertFalse(pending1.isClosed());
          waitForPendingSlotSaturation(port);
        }

        TestWebSocketListener listener = new TestWebSocketListener();

        // Retry briefly if the freed handshake slot cleanup races on the connection thread.
        WebSocket ws = connectWithSlotReleaseRetry(httpClient, port, listener);
        assertNotNull(ws);
        assertTrue(listener.openLatch.await(5, TimeUnit.SECONDS));
        ws.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(5, TimeUnit.SECONDS);
        assertFalse(pending2.isClosed());
      }
    }
  }

  @Test
  @DisplayName("Closing server closes all pending handshake sockets promptly")
  void testServerCloseClosesAllPendingSockets() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    StartedServer started = startCustomServer(TOKEN, handler, Duration.ofSeconds(30), 8);
    int port = started.port();

    try (Socket pending1 = openPartialHandshake(port);
        Socket pending2 = openPartialHandshake(port);
        Socket pending3 = openPartialHandshake(port)) {
      pending1.setSoTimeout(3_000);
      pending2.setSoTimeout(3_000);
      pending3.setSoTimeout(3_000);

      // Give acceptor time to register all three sockets into pendingSockets.
      Thread.sleep(100L);
      started.close();

      assertEquals(-1, pending1.getInputStream().read());
      assertEquals(-1, pending2.getInputStream().read());
      assertEquals(-1, pending3.getInputStream().read());
    } finally {
      started.close();
    }
  }

  @Test
  @DisplayName("Oversized handshake header returns HTTP 431 before closing the socket")
  void testOversizedHandshakeHeaderReturns431() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (StartedServer started = startDefaultServer(TOKEN, handler);
        Socket socket = new Socket("127.0.0.1", started.port())) {
      socket.setSoTimeout(3_000);
      OutputStream out = socket.getOutputStream();
      out.write(
          ("GET /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:" + started.port() + "\r\nX-Large: ")
              .getBytes(StandardCharsets.US_ASCII));
      byte[] chunk = "x".repeat(4096).getBytes(StandardCharsets.US_ASCII);
      for (int i = 0; i < 17; i++) {
        try {
          out.write(chunk);
          out.flush();
        } catch (IOException ignored) {
          break;
        }
      }
      String response = readAllAscii(socket.getInputStream());
      assertTrue(
          response.startsWith("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
          () -> "Expected HTTP 431 response, got: " + response);
    }
  }

  @Test
  @DisplayName("Connection runner aborts activation if server stops before handshake finishes")
  void testRunnerDoesNotActivateSessionWhenStoppedDuringHandshake() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    AtomicBoolean running = new AtomicBoolean(false);
    AtomicReference<AgentServerConnection> activeConnection = new AtomicReference<>();
    AgentWebSocketServer.PendingSockets pendingSockets =
        new AgentWebSocketServer.PendingSockets(running, 4);

    try (ServerSocket listener =
        new ServerSocket(0, 1, new InetSocketAddress("127.0.0.1", 0).getAddress())) {
      int port = listener.getLocalPort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", TOKEN, "test-session", null);
      AgentWebSocketConnectionRunner runner =
          new AgentWebSocketConnectionRunner(
              config, handler, running, activeConnection, pendingSockets, Duration.ofSeconds(5));

      try (Socket client = new Socket("127.0.0.1", port);
          Socket serverSide = listener.accept()) {
        String request =
            "GET /ws/agent HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + port
                + "\r\n"
                + "Upgrade: websocket\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Version: 13\r\n"
                + "Sec-WebSocket-Key: "
                + VALID_WS_KEY
                + "\r\n"
                + "Authorization: Bearer "
                + TOKEN
                + "\r\n\r\n";
        client.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
        client.getOutputStream().flush();

        runner.runConnection(serverSide);

        assertNull(activeConnection.get());
        assertEquals(0, handler.openCount.get());
        assertEquals(0, handler.closeCount.get());
        assertTrue(serverSide.isClosed());
      }
    }
  }

  @Test
  @DisplayName(
      "Reports ws:// endpoint and preserves underlying BindException cause when port is busy")
  void testBindFailureReportsWsEndpointAndCause() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", busyPort, "/ws/agent", TOKEN, "test-session", null);
      try (AgentWebSocketServer server = new AgentWebSocketServer(config, handler)) {
        BindException thrown = assertThrows(BindException.class, server::start);
        assertTrue(
            thrown.getMessage().contains("ws://127.0.0.1:" + busyPort + "/ws/agent"),
            () -> "Expected ws:// endpoint in message, got: " + thrown.getMessage());
        assertInstanceOf(BindException.class, thrown.getCause());
      }
    }
  }

  private static Socket openPartialHandshake(int port) throws IOException {
    Socket socket = new Socket("127.0.0.1", port);
    OutputStream out = socket.getOutputStream();
    out.write(
        ("GET /ws/agent HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nX-Partial: ")
            .getBytes(StandardCharsets.US_ASCII));
    out.flush();
    return socket;
  }

  private static void waitForPendingSlotSaturation(int port) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
    while (System.nanoTime() < deadline) {
      try (Socket excess = new Socket("127.0.0.1", port)) {
        excess.setSoTimeout(2_000);
        String response = readAllAscii(excess.getInputStream());
        if (response.startsWith("HTTP/1.1 503 Service Unavailable\r\n")) {
          return;
        }
      }
      Thread.sleep(20L);
    }
    throw new AssertionError("Expected excess pending connection to be rejected with HTTP 503");
  }

  private static WebSocket connectWithSlotReleaseRetry(
      HttpClient httpClient, int port, TestWebSocketListener listener) throws Exception {
    URI uri = URI.create("ws://127.0.0.1:" + port + "/ws/agent");
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
    while (true) {
      try {
        return httpClient
            .newWebSocketBuilder()
            .header("Authorization", "Bearer " + TOKEN)
            .buildAsync(uri, listener)
            .get(5, TimeUnit.SECONDS);
      } catch (ExecutionException failure) {
        if (failure.getCause() instanceof WebSocketHandshakeException hs
            && hs.getResponse().statusCode() == 503
            && System.nanoTime() < deadline) {
          Thread.sleep(20L);
          continue;
        }
        throw failure;
      }
    }
  }

  private static String sendRawRequest(int port, String rawRequest) throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(3_000);
      OutputStream out = socket.getOutputStream();
      out.write(rawRequest.getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return readAllAscii(socket.getInputStream());
    }
  }

  private static String readAllAscii(InputStream input) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] chunk = new byte[256];
    int read;
    while ((read = input.read(chunk)) >= 0) {
      buffer.write(chunk, 0, read);
    }
    return buffer.toString(StandardCharsets.US_ASCII);
  }

  private static int readStatusCode(InputStream input) throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    int prev = -1;
    while (true) {
      int b = input.read();
      if (b < 0) {
        break;
      }
      line.write(b);
      if (prev == '\r' && b == '\n') {
        break;
      }
      prev = b;
    }
    String statusLine = line.toString(StandardCharsets.US_ASCII).trim();
    String[] parts = statusLine.split(" ");
    assertTrue(parts.length >= 2, () -> "Unexpected HTTP status line: " + statusLine);
    return Integer.parseInt(parts[1]);
  }

  private static StartedServer startDefaultServer(
      String token, AgentWebSocketServer.Handler handler) throws IOException {
    for (int attempt = 0; attempt < 5; attempt++) {
      int port = findFreePort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", token, "test-session", null);
      AgentWebSocketServer server = new AgentWebSocketServer(config, handler);
      try {
        server.start();
        return new StartedServer(server, port);
      } catch (BindException retry) {
        server.close();
        if (attempt == 4) {
          throw retry;
        }
      }
    }
    throw new IllegalStateException("Failed to start server");
  }

  private static StartedServer startCustomServer(
      String token,
      AgentWebSocketServer.Handler handler,
      Duration handshakeTimeout,
      int maxPendingSockets)
      throws IOException {
    for (int attempt = 0; attempt < 5; attempt++) {
      int port = findFreePort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", token, "test-session", null);
      AgentWebSocketServer server =
          new AgentWebSocketServer(config, handler, handshakeTimeout, maxPendingSockets);
      try {
        server.start();
        return new StartedServer(server, port);
      } catch (BindException retry) {
        server.close();
        if (attempt == 4) {
          throw retry;
        }
      }
    }
    throw new IllegalStateException("Failed to start server");
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket()) {
      socket.setReuseAddress(true);
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      return socket.getLocalPort();
    }
  }

  private record StartedServer(AgentWebSocketServer server, int port) implements AutoCloseable {
    @Override
    public void close() {
      server.close();
    }
  }

  private static final class RecordingHandler implements AgentWebSocketServer.Handler {
    private final AtomicInteger openCount = new AtomicInteger();
    private final AtomicInteger closeCount = new AtomicInteger();
    private final CountDownLatch firstCloseLatch = new CountDownLatch(1);

    @Override
    public void onOpen(AgentWebSocketServer.Connection connection) {
      openCount.incrementAndGet();
    }

    @Override
    public void onText(AgentWebSocketServer.Connection connection, String message) {
      connection.sendText("echo:" + message);
    }

    @Override
    public void onClose(AgentWebSocketServer.Connection connection, int statusCode, String reason) {
      closeCount.incrementAndGet();
      firstCloseLatch.countDown();
    }

    @Override
    public void onConnectionError(AgentWebSocketServer.Connection connection, Throwable error) {}

    @Override
    public void onServerError(Throwable error) {}
  }

  private static final class TestWebSocketListener implements WebSocket.Listener {
    private final CountDownLatch openLatch = new CountDownLatch(1);
    private final BlockingQueue<String> messages = new LinkedBlockingQueue<>();
    private final StringBuilder partial = new StringBuilder();

    @Override
    public void onOpen(WebSocket webSocket) {
      openLatch.countDown();
      webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
      partial.append(data);
      if (last) {
        messages.add(partial.toString());
        partial.setLength(0);
      }
      webSocket.request(1);
      return CompletableFuture.completedFuture(null);
    }
  }
}
