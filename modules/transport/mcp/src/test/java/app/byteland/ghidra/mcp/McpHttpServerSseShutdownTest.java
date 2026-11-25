package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

class McpHttpServerSseShutdownTest {

  @Test
  void concurrentSseClientsDeliverEventsAvoidSleepAndCloseQuickly() throws Exception {
    List<Throwable> uncaught = new CopyOnWriteArrayList<>();
    Thread.UncaughtExceptionHandler previousHandler = Thread.getDefaultUncaughtExceptionHandler();
    Thread.setDefaultUncaughtExceptionHandler((thread, error) -> uncaught.add(error));
    List<String> requestLogs = new CopyOnWriteArrayList<>();
    try (ServerHarness harness = ServerHarness.start(requestLogs::add, null)) {
      int clientCount = 8;
      List<SseClient> clients = new ArrayList<>();
      try {
        for (int i = 0; i < clientCount; i++) {
          clients.add(SseClient.connect(harness.port));
        }

        for (int i = 0; i < clientCount; i++) {
          SseClient client = clients.get(i);
          assertTrue(client.endpoint.startsWith("/mcp?sessionId="));
          int status =
              postJsonRpc(
                  harness.port,
                  client.endpoint,
                  "{\"jsonrpc\":\"2.0\",\"id\":" + (i + 1) + ",\"method\":\"ping\",\"params\":{}}");
          assertEquals(202, status);

          String messageData = client.readNextDataForEvent("message");
          @SuppressWarnings("unchecked")
          Map<String, Object> parsed = (Map<String, Object>) JsonUtil.parse(messageData);
          assertEquals("2.0", parsed.get("jsonrpc"));
          assertEquals(i + 1, ((Number) parsed.get("id")).intValue());
          assertEquals(Map.of(), parsed.get("result"));
        }

        Thread.sleep(50L);
        assertEquals(0, countMcpThreadsInThreadSleep());

        long closeStartNanos = System.nanoTime();
        harness.server.close();
        long closeElapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closeStartNanos);

        assertTrue(
            closeElapsedMs < 1_000L,
            "Expected sub-second McpHttpServer.close() with active SSE clients, got "
                + closeElapsedMs
                + " ms");
        assertTrue(harness.server.awaitShutdown(() -> false));

        long sseGetLogs =
            requestLogs.stream().filter(line -> line.contains(" GET - ok 200 ")).count();
        long pingPostLogs =
            requestLogs.stream().filter(line -> line.contains(" ping - ok 202 ")).count();
        assertEquals(clientCount, sseGetLogs);
        assertEquals(clientCount, pingPostLogs);
        assertEquals(List.of(), uncaught, "Expected no uncaught exceptions on virtual threads");
      } finally {
        for (SseClient client : clients) {
          client.close();
        }
      }
    } finally {
      Thread.setDefaultUncaughtExceptionHandler(previousHandler);
    }
  }

  @Test
  void sseKeepaliveCommentsAreSentOnTimeoutAndStopImmediatelyOnClose() throws Exception {
    try (ServerHarness harness = ServerHarness.start(ignored -> {}, 60L)) {
      try (SseClient client = SseClient.connect(harness.port)) {
        String firstKeepalive = client.readNextCommentLine();
        String secondKeepalive = client.readNextCommentLine();
        assertEquals(": keepalive", firstKeepalive);
        assertEquals(": keepalive", secondKeepalive);

        long closeStartNanos = System.nanoTime();
        harness.server.close();
        long closeElapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closeStartNanos);
        assertTrue(
            closeElapsedMs < 1_000L,
            "Expected immediate wakeup on close(), got " + closeElapsedMs + " ms");

        // Drain any left-over lines; stream must reach EOF promptly after close().
        while (client.reader.readLine() != null) {
          // drain to EOF
        }
      }
    }
  }

  @Test
  void disconnectedClientSessionIsRemovedOnWriteFailure() throws Exception {
    try (ServerHarness harness = ServerHarness.start(ignored -> {}, 40L)) {
      String endpoint;
      try (SseClient client = SseClient.connect(harness.port)) {
        endpoint = client.endpoint;
        client.abortWithReset();
      }

      long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
      int status = 202;
      while (System.nanoTime() < deadlineNanos) {
        status =
            postJsonRpc(
                harness.port,
                endpoint,
                "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\",\"params\":{}}");
        if (status == 404) {
          break;
        }
        Thread.sleep(25L);
      }
      assertEquals(404, status, "Disconnected SSE session should be evicted and return HTTP 404");
    }
  }

  @Test
  void sseSessionCloseSignalsWaitersWithoutAcquiringWriteLock() throws Exception {
    CountDownLatch writeEntered = new CountDownLatch(1);
    CountDownLatch unblockWrite = new CountDownLatch(1);
    BlockingExchange exchange = new BlockingExchange(writeEntered, unblockWrite);
    McpHttpServer.SseSession session = new McpHttpServer.SseSession(exchange);

    CountDownLatch waiterWoke = new CountDownLatch(1);
    AtomicBoolean signaled = new AtomicBoolean(false);
    Thread waiter =
        Thread.ofVirtual()
            .start(
                () -> {
                  try {
                    signaled.set(session.awaitClose(15, TimeUnit.SECONDS));
                  } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                  } finally {
                    waiterWoke.countDown();
                  }
                });

    Thread stalledWriter =
        Thread.ofVirtual()
            .start(
                () -> {
                  try {
                    session.sendEvent("message", "{\"ok\":true}");
                  } catch (IOException ignored) {
                  }
                });

    assertTrue(writeEntered.await(2, TimeUnit.SECONDS), "Writer should enter OutputStream.write");

    CountDownLatch closeFinished = new CountDownLatch(1);
    Thread closer =
        Thread.ofVirtual()
            .start(
                () -> {
                  session.close();
                  closeFinished.countDown();
                });

    try {
      assertTrue(
          waiterWoke.await(500, TimeUnit.MILLISECONDS),
          "close() must signal closeLatch even while writeLock is held by a stalled socket write");
      assertTrue(signaled.get());
      assertFalse(session.isActive());
      assertTrue(
          closeFinished.await(500, TimeUnit.MILLISECONDS),
          "close() must not block on writeLock");
    } finally {
      unblockWrite.countDown();
      stalledWriter.join(2_000L);
      waiter.join(2_000L);
      closer.join(2_000L);
    }
  }

  @Test
  void interruptedWaitRestoresInterruptStatus() throws Exception {
    BlockingExchange exchange =
        new BlockingExchange(new CountDownLatch(0), new CountDownLatch(0), false);
    McpHttpServer.SseSession session = new McpHttpServer.SseSession(exchange);

    CountDownLatch startedWaiting = new CountDownLatch(1);
    CountDownLatch finished = new CountDownLatch(1);
    AtomicBoolean interruptRestored = new AtomicBoolean(false);

    Thread handlerThread =
        Thread.ofVirtual()
            .start(
                () -> {
                  startedWaiting.countDown();
                  try {
                    session.awaitClose(15, TimeUnit.SECONDS);
                  } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    interruptRestored.set(Thread.currentThread().isInterrupted());
                  } finally {
                    session.close();
                    finished.countDown();
                  }
                });

    assertTrue(startedWaiting.await(2, TimeUnit.SECONDS));
    Thread.sleep(30L);
    handlerThread.interrupt();

    assertTrue(finished.await(2, TimeUnit.SECONDS));
    assertTrue(interruptRestored.get(), "Interrupt flag should be restored on InterruptedException");
    assertNull(exchange.getPrincipal());
  }

  private static int postJsonRpc(int port, String relativeEndpoint, String jsonBody)
      throws IOException {
    URI uri = URI.create("http://127.0.0.1:" + port + relativeEndpoint);
    HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
    connection.setConnectTimeout(3_000);
    connection.setReadTimeout(3_000);
    connection.setRequestMethod("POST");
    connection.setDoOutput(true);
    connection.setRequestProperty("Content-Type", "application/json");
    byte[] payload = jsonBody.getBytes(StandardCharsets.UTF_8);
    try (OutputStream out = connection.getOutputStream()) {
      out.write(payload);
    }
    try {
      return connection.getResponseCode();
    } finally {
      connection.disconnect();
    }
  }

  private static int countMcpThreadsInThreadSleep() {
    int count = 0;
    for (Map.Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
      boolean inSleep = false;
      boolean inMcpServer = false;
      for (StackTraceElement frame : entry.getValue()) {
        if ("java.lang.Thread".equals(frame.getClassName())
            && "sleep".equals(frame.getMethodName())) {
          inSleep = true;
        }
        if (frame.getClassName().startsWith("app.byteland.ghidra.mcp.McpHttpServer")) {
          inMcpServer = true;
        }
      }
      if (inSleep && inMcpServer) {
        count++;
      }
    }
    return count;
  }

  private static final class SseClient implements AutoCloseable {
    private final Socket socket;
    private final BufferedReader reader;
    private final String endpoint;

    private SseClient(Socket socket, BufferedReader reader, String endpoint) {
      this.socket = socket;
      this.reader = reader;
      this.endpoint = endpoint;
    }

    static SseClient connect(int port) throws IOException {
      Socket socket = new Socket("127.0.0.1", port);
      socket.setSoTimeout(3_000);
      OutputStream out = socket.getOutputStream();
      String request =
          "GET /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Accept: text/event-stream\r\n\r\n";
      out.write(request.getBytes(StandardCharsets.UTF_8));
      out.flush();

      BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
      String statusLine = reader.readLine();
      if (statusLine == null || !statusLine.contains("200")) {
        socket.close();
        throw new IOException("Unexpected SSE HTTP status line: " + statusLine);
      }
      String headerLine;
      while ((headerLine = reader.readLine()) != null && !headerLine.isEmpty()) {
        // consume response headers
      }
      SseClient client = new SseClient(socket, reader, "");
      String endpoint = client.readNextDataForEvent("endpoint");
      return new SseClient(socket, reader, endpoint);
    }

    String readNextDataForEvent(String expectedEvent) throws IOException {
      String currentEvent = null;
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith("event: ")) {
          currentEvent = line.substring("event: ".length()).trim();
        } else if (line.startsWith("data: ") && expectedEvent.equals(currentEvent)) {
          return line.substring("data: ".length()).trim();
        }
      }
      throw new IOException("EOF while waiting for SSE event: " + expectedEvent);
    }

    String readNextCommentLine() throws IOException {
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.startsWith(": ")) {
          return line;
        }
      }
      throw new IOException("EOF while waiting for SSE keepalive comment");
    }

    void abortWithReset() throws IOException {
      socket.setSoLinger(true, 0);
      socket.close();
    }

    @Override
    public void close() {
      try {
        socket.close();
      } catch (IOException ignored) {
      }
    }
  }

  private static final class ServerHarness implements AutoCloseable {
    private final int port;
    private final AgentDispatcher dispatcher;
    private final McpHttpServer server;

    private ServerHarness(int port, AgentDispatcher dispatcher, McpHttpServer server) {
      this.port = port;
      this.dispatcher = dispatcher;
      this.server = server;
    }

    static ServerHarness start(Consumer<String> logSink, Long keepaliveMillis) throws IOException {
      BridgeServices services = stubServices();
      IOException lastBindFailure = null;
      for (int attempt = 0; attempt < 5; attempt++) {
        int candidatePort;
        try (ServerSocket probe = new ServerSocket(0)) {
          candidatePort = probe.getLocalPort();
        }
        McpConfig mcpConfig =
            new McpConfig("127.0.0.1", candidatePort, "/mcp", null, "test-session", "ghidra");
        AgentConfig agentConfig =
            new AgentConfig(null, "127.0.0.1", candidatePort, "/mcp", null, "test-session", null);
        AgentDispatcher dispatcher = new AgentDispatcher(services, agentConfig);
        try {
          McpHttpServer server =
              keepaliveMillis == null
                  ? new McpHttpServer(mcpConfig, dispatcher, logSink)
                  : new McpHttpServer(mcpConfig, dispatcher, logSink, keepaliveMillis);
          server.start();
          return new ServerHarness(candidatePort, dispatcher, server);
        } catch (BindException bindFailure) {
          dispatcher.close();
          lastBindFailure = bindFailure;
        }
      }
      throw lastBindFailure;
    }

    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
  }

  private static BridgeServices stubServices() {
    TransactionRunner tx =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        unused(CommentService.class),
        unused(ReferenceService.class),
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        unused(AnalysisService.class),
        unused(DecompilationService.class),
        unused(SymbolService.class),
        unused(DataTypeService.class),
        tx,
        "test-program");
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              throw new AssertionError("Unexpected service call: " + method.getName());
            }));
  }

  private static final class BlockingExchange extends HttpExchange {
    private final Headers requestHeaders = new Headers();
    private final Headers responseHeaders = new Headers();
    private final OutputStream responseBody;

    BlockingExchange(CountDownLatch writeEntered, CountDownLatch unblockWrite) {
      this(writeEntered, unblockWrite, true);
    }

    BlockingExchange(
        CountDownLatch writeEntered, CountDownLatch unblockWrite, boolean blockWrites) {
      this.responseBody =
          new OutputStream() {
            @Override
            public void write(int b) throws IOException {
              write(new byte[] {(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
              if (!blockWrites) {
                return;
              }
              writeEntered.countDown();
              try {
                unblockWrite.await();
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted write", interrupted);
              }
            }
          };
    }

    @Override
    public Headers getRequestHeaders() {
      return requestHeaders;
    }

    @Override
    public Headers getResponseHeaders() {
      return responseHeaders;
    }

    @Override
    public URI getRequestURI() {
      return URI.create("/mcp");
    }

    @Override
    public String getRequestMethod() {
      return "GET";
    }

    @Override
    public HttpContext getHttpContext() {
      return null;
    }

    @Override
    public void close() {}

    @Override
    public InputStream getRequestBody() {
      return InputStream.nullInputStream();
    }

    @Override
    public OutputStream getResponseBody() {
      return responseBody;
    }

    @Override
    public void sendResponseHeaders(int rCode, long responseLength) {}

    @Override
    public InetSocketAddress getRemoteAddress() {
      return null;
    }

    @Override
    public int getResponseCode() {
      return 200;
    }

    @Override
    public InetSocketAddress getLocalAddress() {
      return null;
    }

    @Override
    public String getProtocol() {
      return "HTTP/1.1";
    }

    @Override
    public Object getAttribute(String name) {
      return null;
    }

    @Override
    public void setAttribute(String name, Object value) {}

    @Override
    public void setStreams(InputStream i, OutputStream o) {}

    @Override
    public HttpPrincipal getPrincipal() {
      return null;
    }
  }
}
