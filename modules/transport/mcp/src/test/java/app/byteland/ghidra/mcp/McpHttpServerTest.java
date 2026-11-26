package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
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
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

class McpHttpServerTest {

  @Test
  void concurrentSseAndStalledPostsKeepPlatformThreadsBounded() throws Exception {
    try (TestServerHandle handle = startServer(() -> createDispatcher(null), null, null)) {
      int port = handle.port();
      long baselinePlatformThreads = countPlatformThreads();

      String sseReq =
          "GET /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Accept: text/event-stream\r\n\r\n";
      String stalledPostReq =
          "POST /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Content-Type: application/json\r\n"
              + "MCP-Protocol-Version: 2025-11-25\r\n"
              + "Content-Length: 256\r\n\r\n"
              + "{";

      List<Socket> openSockets = new CopyOnWriteArrayList<>();
      try (ExecutorService clientPool = Executors.newVirtualThreadPerTaskExecutor()) {
        List<Callable<Integer>> sseTasks = new ArrayList<>();
        for (int i = 0; i < 80; i++) {
          sseTasks.add(
              () -> {
                Socket socket = openRawSocket(port, sseReq);
                openSockets.add(socket);
                return readHttpStatusCode(socket);
              });
        }
        List<Future<Integer>> sseFutures = clientPool.invokeAll(sseTasks);

        int sseOkCount = 0;
        int sseBusyCount = 0;
        for (Future<Integer> future : sseFutures) {
          int status = future.get(5, TimeUnit.SECONDS);
          if (status == 200) {
            sseOkCount++;
          } else if (status == 503) {
            sseBusyCount++;
          } else {
            throw new AssertionError("Unexpected SSE GET status: " + status);
          }
        }
        assertEquals(McpHttpServer.MAX_SSE_SESSIONS, sseOkCount);
        assertEquals(80 - McpHttpServer.MAX_SSE_SESSIONS, sseBusyCount);

        List<Future<Integer>> postStatuses = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
          Socket socket = openRawSocket(port, stalledPostReq);
          openSockets.add(socket);
          socket.setSoTimeout(800);
          postStatuses.add(
              clientPool.submit(
                  () -> {
                    try {
                      return readHttpStatusCode(socket);
                    } catch (IOException blockedInReadBody) {
                      return -1;
                    }
                  }));
        }

        int stalledInFlight = 0;
        int rejectedPostBusy = 0;
        for (Future<Integer> future : postStatuses) {
          int status = future.get(5, TimeUnit.SECONDS);
          if (status == -1) {
            stalledInFlight++;
          } else if (status == 503) {
            rejectedPostBusy++;
          } else {
            throw new AssertionError("Unexpected stalled POST status: " + status);
          }
        }
        assertEquals(McpHttpServer.MAX_CONCURRENT_REQUESTS, stalledInFlight);
        assertEquals(100 - McpHttpServer.MAX_CONCURRENT_REQUESTS, rejectedPostBusy);

        // When SSE and POST permits are full, virtual-thread handlers still respond fast
        // without carrier-thread pinning.
        String headReq = "HEAD /mcp HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n";
        try (Socket headSocket = openRawSocket(port, headReq)) {
          assertEquals(200, readHttpStatusCode(headSocket));
        }
        String optionsReq = "OPTIONS /mcp HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n";
        try (Socket optionsSocket = openRawSocket(port, optionsReq)) {
          assertEquals(204, readHttpStatusCode(optionsSocket));
        }
        String putReq = "PUT /mcp HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\n\r\n";
        try (Socket putSocket = openRawSocket(port, putReq)) {
          assertEquals(405, readHttpStatusCode(putSocket));
        }

        long loadedPlatformThreads = countPlatformThreads();
        long platformThreadGrowth = loadedPlatformThreads - baselinePlatformThreads;
        assertTrue(
            platformThreadGrowth <= McpHttpServer.MAX_CONCURRENT_REQUESTS + 16,
            "Platform threads grew excessively under 180 concurrent sockets: baseline="
                + baselinePlatformThreads
                + ", loaded="
                + loadedPlatformThreads);
      } finally {
        for (Socket socket : openSockets) {
          closeQuietly(socket);
        }
      }
    }
  }

  @Test
  void sseCompatibilityCapMessageDeliveryAndPermitRelease() throws Exception {
    Duration fastKeepalive = Duration.ofMillis(100);
    try (TestServerHandle handle =
        startServer(() -> createDispatcher(null), Duration.ofSeconds(2), fastKeepalive)) {
      HttpClient client =
          HttpClient.newBuilder()
              .version(HttpClient.Version.HTTP_1_1)
              .connectTimeout(Duration.ofSeconds(3))
              .build();
      URI baseUri = URI.create("http://127.0.0.1:" + handle.port() + "/mcp");

      // Unsupported HTTP methods return `405` with the `Allow` header.
      HttpResponse<String> deleteResponse =
          client.send(
              HttpRequest.newBuilder(baseUri).DELETE().build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(405, deleteResponse.statusCode());
      assertEquals("POST, GET, OPTIONS", deleteResponse.headers().firstValue("Allow").orElse(null));

      List<Stream<String>> sseStreams = new ArrayList<>();
      List<Iterator<String>> sseIterators = new ArrayList<>();
      List<String> endpointPaths = new ArrayList<>();
      try {
        for (int i = 0; i < McpHttpServer.MAX_SSE_SESSIONS; i++) {
          HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(baseUri).GET();
          if (i == 1) {
            requestBuilder.header("Accept", "*/*");
          } else if (i == 2) {
            requestBuilder.header("Accept", "application/json, text/event-stream");
          } else if (i > 2) {
            requestBuilder.header("Accept", "text/event-stream");
          }
          // Index 0 sends `GET /mcp` with no `Accept` header to check legacy client compatibility.
          HttpResponse<Stream<String>> sseResponse =
              client.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofLines());
          assertEquals(200, sseResponse.statusCode());
          Stream<String> lines = sseResponse.body();
          sseStreams.add(lines);
          Iterator<String> iterator = lines.iterator();
          sseIterators.add(iterator);
          String endpointUri = readNextSseEventData(iterator, "endpoint");
          assertTrue(endpointUri.startsWith("/mcp?sessionId="), endpointUri);
          endpointPaths.add(endpointUri);
        }

        // The next SSE stream above `MAX_SSE_SESSIONS` receives `503`.
        HttpResponse<String> overflowSse =
            client.send(
                HttpRequest.newBuilder(baseUri)
                    .GET()
                    .header("Accept", "text/event-stream")
                    .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(503, overflowSse.statusCode());

        // `POST` to the first SSE session returns `202` and sends a `message` event over SSE.
        URI sessionUri = URI.create("http://127.0.0.1:" + handle.port() + endpointPaths.get(0));
        HttpResponse<String> pingPost =
            client.send(
                HttpRequest.newBuilder(sessionUri)
                    .header("Content-Type", "application/json")
                    .header("MCP-Protocol-Version", "2025-11-25")
                    .POST(
                        HttpRequest.BodyPublishers.ofString(
                            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\",\"params\":{}}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(202, pingPost.statusCode());

        String messageData = readNextSseEventData(sseIterators.get(0), "message");
        @SuppressWarnings("unchecked")
        Map<String, Object> parsedMessage = (Map<String, Object>) JsonUtil.parse(messageData);
        assertEquals(7L, ((Number) parsedMessage.get("id")).longValue());

        // Close one SSE client stream. The next keepalive write detects the disconnect and frees
        // the permit.
        sseStreams.remove(0).close();
        sseIterators.remove(0);

        boolean reopened = false;
        long deadlineNanos = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (System.nanoTime() < deadlineNanos) {
          HttpResponse<Stream<String>> replacement =
              client.send(
                  HttpRequest.newBuilder(baseUri)
                      .GET()
                      .header("Accept", "text/event-stream")
                      .build(),
                  HttpResponse.BodyHandlers.ofLines());
          if (replacement.statusCode() == 200) {
            sseStreams.add(replacement.body());
            reopened = true;
            break;
          }
          replacement.body().close();
          Thread.sleep(40L);
        }
        assertTrue(reopened, "Expected closed SSE session permit to be released");
      } finally {
        for (Stream<String> stream : sseStreams) {
          stream.close();
        }
      }
    }
  }

  @Test
  void stalledPostTimeoutClosesExchangeAndReleasesPermits() throws Exception {
    List<String> logs = new CopyOnWriteArrayList<>();
    try (TestServerHandle handle =
        startServer(
            () -> createDispatcher(null),
            Duration.ofMillis(250),
            Duration.ofSeconds(15),
            logs::add)) {
      int port = handle.port();
      String stalledPostReq =
          "POST /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Content-Type: application/json\r\n"
              + "MCP-Protocol-Version: 2025-11-25\r\n"
              + "Content-Length: 256\r\n\r\n"
              + "{";

      List<Socket> stalledSockets = new ArrayList<>();
      try {
        for (int i = 0; i < McpHttpServer.MAX_CONCURRENT_REQUESTS; i++) {
          Socket socket = openRawSocket(port, stalledPostReq);
          socket.setSoTimeout(2000);
          stalledSockets.add(socket);
        }

        // Wait for the 250 ms read time limit to close all stalled sockets.
        for (Socket socket : stalledSockets) {
          int readResult;
          try {
            readResult = socket.getInputStream().read();
          } catch (IOException resetByPeer) {
            readResult = -1;
          }
          assertEquals(-1, readResult, "Expected server to close stalled POST socket");
        }
      } finally {
        for (Socket socket : stalledSockets) {
          closeQuietly(socket);
        }
      }

      // Send `MAX_CONCURRENT_REQUESTS` valid `POST` requests to check that all permits are free.
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
      URI uri = URI.create("http://127.0.0.1:" + port + "/mcp");
      for (int i = 0; i < McpHttpServer.MAX_CONCURRENT_REQUESTS; i++) {
        HttpResponse<String> response =
            client.send(
                HttpRequest.newBuilder(uri)
                    .header("Content-Type", "application/json")
                    .header("MCP-Protocol-Version", "2025-11-25")
                    .POST(
                        HttpRequest.BodyPublishers.ofString(
                            "{\"jsonrpc\":\"2.0\",\"id\":"
                                + (i + 1)
                                + ",\"method\":\"ping\",\"params\":{}}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
      }
      assertTrue(
          logs.stream().anyMatch(entry -> entry.contains(" 408 ") && entry.contains("timed out")),
          "Expected request log to record 408 timeout");
    }
  }

  @Test
  void concurrentRequestSemaphoreReturns503AndReleasesAfterCompletion() throws Exception {
    try (TestServerHandle handle = startServer(() -> createDispatcher(null), null, null)) {
      int port = handle.port();
      HttpClient client =
          HttpClient.newBuilder()
              .version(HttpClient.Version.HTTP_1_1)
              .connectTimeout(Duration.ofSeconds(3))
              .build();
      URI uri = URI.create("http://127.0.0.1:" + port + "/mcp");

      String fullPingBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}";
      byte[] bodyBytes = fullPingBody.getBytes(StandardCharsets.UTF_8);
      String partialHeaderAndBody =
          "POST /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Content-Type: application/json\r\n"
              + "MCP-Protocol-Version: 2025-11-25\r\n"
              + "Content-Length: "
              + bodyBytes.length
              + "\r\n\r\n"
              + fullPingBody.substring(0, fullPingBody.length() - 1);

      List<Socket> inFlightSockets = new ArrayList<>();
      try {
        for (int i = 0; i < McpHttpServer.MAX_CONCURRENT_REQUESTS; i++) {
          Socket socket = openRawSocket(port, partialHeaderAndBody);
          socket.setSoTimeout(3000);
          inFlightSockets.add(socket);
        }

        // Wait until all 32 virtual threads enter `JsonRpcHandler` and take permits.
        long waitDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (handle.server().availableRequestPermits() > 0
            && System.nanoTime() < waitDeadline) {
          Thread.sleep(10L);
        }
        assertEquals(
            0,
            handle.server().availableRequestPermits(),
            "Expected all 32 in-flight POST requests to hold request permits");

        HttpResponse<String> probe =
            client.send(
                HttpRequest.newBuilder(uri)
                    .header("Content-Type", "application/json")
                    .header("MCP-Protocol-Version", "2025-11-25")
                    .POST(
                        HttpRequest.BodyPublishers.ofString(
                            "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\",\"params\":{}}"))
                    .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(
            503,
            probe.statusCode(),
            "Expected 33rd concurrent POST request to receive HTTP 503");

        // Keep the first 8 sockets stalled and complete sockets 8..31 first.
        // Stalled reads must not block later `POST` requests.
        for (int i = 8; i < inFlightSockets.size(); i++) {
          OutputStream out = inFlightSockets.get(i).getOutputStream();
          out.write('}');
          out.flush();
        }
        for (int i = 8; i < inFlightSockets.size(); i++) {
          assertEquals(200, readHttpStatusCode(inFlightSockets.get(i)));
        }

        for (int i = 0; i < 8; i++) {
          OutputStream out = inFlightSockets.get(i).getOutputStream();
          out.write('}');
          out.flush();
        }
        for (int i = 0; i < 8; i++) {
          assertEquals(200, readHttpStatusCode(inFlightSockets.get(i)));
        }
      } finally {
        for (Socket socket : inFlightSockets) {
          closeQuietly(socket);
        }
      }

      HttpResponse<String> afterRelease =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Content-Type", "application/json")
                  .header("MCP-Protocol-Version", "2025-11-25")
                  .POST(
                      HttpRequest.BodyPublishers.ofString(
                          "{\"jsonrpc\":\"2.0\",\"id\":100,\"method\":\"ping\",\"params\":{}}"))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(200, afterRelease.statusCode());
    }
  }

  private static String readNextSseEventData(Iterator<String> lines, String expectedEvent) {
    String currentEvent = null;
    while (lines.hasNext()) {
      String line = lines.next();
      if (line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("event: ")) {
        currentEvent = line.substring("event: ".length());
      } else if (line.startsWith("data: ") && expectedEvent.equals(currentEvent)) {
        return line.substring("data: ".length());
      }
    }
    throw new AssertionError("SSE stream closed before receiving event: " + expectedEvent);
  }

  private static Socket openRawSocket(int port, String rawHttpRequest) throws IOException {
    Socket socket = new Socket();
    socket.connect(new InetSocketAddress("127.0.0.1", port), 3000);
    OutputStream out = socket.getOutputStream();
    out.write(rawHttpRequest.getBytes(StandardCharsets.UTF_8));
    out.flush();
    return socket;
  }

  private static int readHttpStatusCode(Socket socket) throws IOException {
    StringBuilder line = new StringBuilder();
    var input = socket.getInputStream();
    int b;
    while ((b = input.read()) != -1) {
      if (b == '\n') {
        break;
      }
      if (b != '\r') {
        line.append((char) b);
      }
    }
    String statusLine = line.toString();
    String[] parts = statusLine.split(" ");
    if (parts.length < 2) {
      throw new IOException("Invalid HTTP status line: " + statusLine);
    }
    return Integer.parseInt(parts[1]);
  }

  private static long countPlatformThreads() {
    return Thread.getAllStackTraces().keySet().stream().filter(t -> !t.isVirtual()).count();
  }

  private static void closeQuietly(Socket socket) {
    try {
      socket.close();
    } catch (IOException ignored) {
    }
  }

  private static TestServerHandle startServer(
      Supplier<AgentDispatcher> dispatcherFactory,
      Duration bodyReadTimeout,
      Duration sseKeepaliveInterval)
      throws IOException {
    return startServer(dispatcherFactory, bodyReadTimeout, sseKeepaliveInterval, ignored -> {});
  }

  private static TestServerHandle startServer(
      Supplier<AgentDispatcher> dispatcherFactory,
      Duration bodyReadTimeout,
      Duration sseKeepaliveInterval,
      Consumer<String> logSink)
      throws IOException {
    BindException lastBindError = null;
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = findFreePort();
      AgentDispatcher dispatcher = dispatcherFactory.get();
      McpConfig config = new McpConfig("127.0.0.1", port, "/mcp", null, "test-session", "ghidra");
      try {
        McpHttpServer server =
            bodyReadTimeout == null && sseKeepaliveInterval == null
                ? new McpHttpServer(config, dispatcher, logSink)
                : new McpHttpServer(
                    config,
                    dispatcher,
                    logSink,
                    bodyReadTimeout == null
                        ? McpHttpServer.DEFAULT_BODY_READ_TIMEOUT
                        : bodyReadTimeout,
                    sseKeepaliveInterval == null
                        ? McpHttpServer.DEFAULT_SSE_KEEPALIVE_INTERVAL
                        : sseKeepaliveInterval);
        server.start();
        return new TestServerHandle(port, dispatcher, server);
      } catch (BindException bindError) {
        dispatcher.close();
        lastBindError = bindError;
      }
    }
    throw lastBindError;
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static AgentDispatcher createDispatcher(Runnable onProgramGet) {
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("getProgram".equals(method)) {
                if (onProgramGet != null) {
                  onProgramGet.run();
                }
                return new ProgramResource(
                    "test.bin",
                    "/test.bin",
                    "ELF",
                    "ram:00100000",
                    "ram:00100000",
                    "ram:00101000",
                    "x86:LE:64:default",
                    "gcc",
                    Instant.EPOCH,
                    Instant.EPOCH,
                    1L,
                    1L);
              }
              throw new AssertionError("Unexpected ProgramService call: " + method);
            });
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (method, args) -> {
              if ("close".equals(method)) {
                return null;
              }
              throw new AssertionError("Unexpected AnalysisService call: " + method);
            });
    DecompilationService decompilationService =
        proxy(
            DecompilationService.class,
            (method, args) -> {
              if ("close".equals(method)) {
                return null;
              }
              throw new AssertionError("Unexpected DecompilationService call: " + method);
            });
    TransactionRunner transactionRunner =
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
    BridgeServices services =
        new BridgeServices(
            programService,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysisService,
            decompilationService,
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactionRunner,
            "test.bin");
    return new AgentDispatcher(services, "test-session");
  }

  private interface Invocation {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("Unexpected call: " + method);
        });
  }

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> invocation.invoke(method.getName(), args)));
  }

  private record TestServerHandle(int port, AgentDispatcher dispatcher, McpHttpServer server)
      implements AutoCloseable {
    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
  }
}
