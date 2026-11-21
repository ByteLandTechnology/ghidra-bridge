package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class McpHttpServerHardeningTest {

  @Test
  void rejectsExternalOriginAndForgedHostWith403AndReflectsOnlyPermittedOrigins()
      throws Exception {
    try (ServerHandle handle = startServer(16, 15_000L, () -> {})) {
      HttpClient client = HttpClient.newHttpClient();
      URI uri = URI.create("http://127.0.0.1:" + handle.port() + "/mcp");

      HttpResponse<String> evilOriginPost =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Origin", "https://evil.example")
                  .header("Content-Type", "application/json")
                  .POST(HttpRequest.BodyPublishers.ofString(pingBody()))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(403, evilOriginPost.statusCode());
      assertTrue(evilOriginPost.headers().firstValue("Access-Control-Allow-Origin").isEmpty());

      HttpResponse<String> evilOriginPreflight =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Origin", "https://evil.example")
                  .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(403, evilOriginPreflight.statusCode());
      assertTrue(evilOriginPreflight.headers().firstValue("Access-Control-Allow-Origin").isEmpty());

      HttpResponse<String> loopbackPreflight =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Origin", "http://localhost:3000")
                  .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(204, loopbackPreflight.statusCode());
      assertEquals(
          "http://localhost:3000",
          loopbackPreflight.headers().firstValue("Access-Control-Allow-Origin").orElse(""));
      assertEquals("Origin", loopbackPreflight.headers().firstValue("Vary").orElse(""));

      HttpResponse<String> noOriginPreflight =
          client.send(
              HttpRequest.newBuilder(uri)
                  .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(204, noOriginPreflight.statusCode());
      assertTrue(noOriginPreflight.headers().firstValue("Access-Control-Allow-Origin").isEmpty());

      assertEquals(
          403,
          rawHttpStatus(
              handle.port(),
              List.of(
                  "POST /mcp HTTP/1.1",
                  "Host: evil.rebind.example",
                  "Content-Type: application/json",
                  "Content-Length: 2",
                  "Connection: close"),
              "{}"));

      assertEquals(
          403,
          rawHttpStatus(
              handle.port(),
              List.of(
                  "POST /mcp HTTP/1.1",
                  "Host: 127.0.0.1:" + handle.port(),
                  "Host: evil.rebind.example",
                  "Content-Type: application/json",
                  "Content-Length: 2",
                  "Connection: close"),
              "{}"));

      int wrongPort = handle.port() == 65535 ? handle.port() - 1 : handle.port() + 1;
      assertEquals(
          403,
          rawHttpStatus(
              handle.port(),
              List.of(
                  "POST /mcp HTTP/1.1",
                  "Host: 127.0.0.1:" + wrongPort,
                  "Content-Type: application/json",
                  "Content-Length: 2",
                  "Connection: close"),
              "{}"));
    }
  }

  @Test
  void parsesRfc9110ContentTypeAndBoundsRequestBodyTo4MiB() throws Exception {
    assertTrue(McpHttpServer.isJsonContentType("application/json"));
    assertTrue(McpHttpServer.isJsonContentType("Application/JSON; charset=utf-8"));
    assertTrue(McpHttpServer.isJsonContentType("application/json ; charset=\"utf-8\""));
    assertFalse(McpHttpServer.isJsonContentType("application/json-evil"));
    assertFalse(McpHttpServer.isJsonContentType("application/json; malformed"));
    assertFalse(McpHttpServer.isJsonContentType("application/json;"));
    assertFalse(McpHttpServer.isJsonContentType("text/plain"));

    try (ServerHandle handle = startServer(16, 15_000L, () -> {})) {
      HttpClient client = HttpClient.newHttpClient();
      URI uri = URI.create("http://127.0.0.1:" + handle.port() + "/mcp");

      HttpResponse<String> mixedCaseJson =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Content-Type", "Application/JSON; charset=utf-8")
                  .header("MCP-Protocol-Version", "2026-07-28")
                  .header("Mcp-Method", "ping")
                  .POST(HttpRequest.BodyPublishers.ofString(pingBody()))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(200, mixedCaseJson.statusCode());

      HttpResponse<String> evilJsonSubtype =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Content-Type", "application/json-evil")
                  .header("MCP-Protocol-Version", "2026-07-28")
                  .header("Mcp-Method", "ping")
                  .POST(HttpRequest.BodyPublishers.ofString(pingBody()))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(415, evilJsonSubtype.statusCode());

      int oversizedBytes = McpHttpServer.MAX_REQUEST_BODY_BYTES + 256;
      byte[] oversizedPayload = new byte[oversizedBytes];
      oversizedPayload[0] = '{';
      for (int i = 1; i < oversizedBytes - 1; i++) {
        oversizedPayload[i] = ' ';
      }
      oversizedPayload[oversizedBytes - 1] = '}';

      HttpResponse<String> oversizedFixedLength =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Content-Type", "application/json")
                  .POST(HttpRequest.BodyPublishers.ofByteArray(oversizedPayload))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(413, oversizedFixedLength.statusCode());

      HttpResponse<String> oversizedStreaming =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Content-Type", "application/json")
                  .POST(
                      HttpRequest.BodyPublishers.ofInputStream(
                          () -> new java.io.ByteArrayInputStream(oversizedPayload)))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(413, oversizedStreaming.statusCode());
    }
  }

  @Test
  void gatesLegacySseGetCapsConcurrentSessionsAndExecutesOnVirtualThreads() throws Exception {
    assertTrue(
        Modifier.isSynchronized(
            McpHttpServer.SseSession.class.getDeclaredMethod("close").getModifiers()));

    AtomicBoolean observedVirtualThread = new AtomicBoolean(false);
    try (ServerHandle handle =
        startServer(
            2, 100L, () -> observedVirtualThread.set(Thread.currentThread().isVirtual()))) {
      HttpClient client = HttpClient.newHttpClient();
      URI uri = URI.create("http://127.0.0.1:" + handle.port() + "/mcp");

      HttpResponse<String> wildcardAcceptGet =
          client.send(
              HttpRequest.newBuilder(uri).header("Accept", "*/*").GET().build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(405, wildcardAcceptGet.statusCode());
      assertEquals(
          "POST, GET, HEAD, OPTIONS", wildcardAcceptGet.headers().firstValue("Allow").orElse(""));

      HttpResponse<String> zeroWeightGet =
          client.send(
              HttpRequest.newBuilder(uri).header("Accept", "text/event-stream; q=0").GET().build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(405, zeroWeightGet.statusCode());

      HttpResponse<String> modernHeaderGet =
          client.send(
              HttpRequest.newBuilder(uri)
                  .header("Accept", "text/event-stream")
                  .header("MCP-Protocol-Version", "2025-11-25")
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(405, modernHeaderGet.statusCode());

      try (RawSseStream sse1 = openSseStream(handle.port());
          RawSseStream sse2 = openSseStream(handle.port())) {
        assertTrue(sse1.endpointEvent().startsWith("/mcp?sessionId="));
        assertTrue(sse2.endpointEvent().startsWith("/mcp?sessionId="));

        HttpResponse<String> overflowGet =
            client.send(
                HttpRequest.newBuilder(uri).header("Accept", "text/event-stream").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(503, overflowGet.statusCode());

        String languageCall =
            """
            {"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
              "_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{}
              },
              "name":"ghidra_program",
              "arguments":{"operation":"language.get","params":{}}
            }}
            """;
        HttpResponse<String> postWhileSseFull =
            client.send(
                HttpRequest.newBuilder(uri)
                    .header("Content-Type", "application/json")
                    .header("MCP-Protocol-Version", "2026-07-28")
                    .header("Mcp-Method", "tools/call")
                    .header("Mcp-Name", "ghidra_program")
                    .POST(HttpRequest.BodyPublishers.ofString(languageCall))
                    .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, postWhileSseFull.statusCode());
        assertFalse(postWhileSseFull.body().contains("\"isError\":true"));
        assertTrue(observedVirtualThread.get(), "Expected McpHttpServer to run on virtual thread");
      }

      boolean reopened = false;
      for (int attempt = 0; attempt < 25 && !reopened; attempt++) {
        Thread.sleep(50L);
        try (RawSseStream sse3 = tryOpenSseStream(handle.port())) {
          if (sse3 != null && sse3.endpointEvent().startsWith("/mcp?sessionId=")) {
            reopened = true;
          }
        }
      }
      assertTrue(reopened, "Expected SSE session slot to be released after disconnect");
    }
  }

  private static String pingBody() {
    return """
        {"jsonrpc":"2.0","id":1,"method":"ping","params":{
          "_meta":{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":{}
          }
        }}
        """;
  }

  private static ServerHandle startServer(
      int maxSseSessions, long sseKeepaliveMillis, Runnable onSaveProgram) throws IOException {
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = freePort();
      AgentDispatcher dispatcher = newDispatcher(onSaveProgram, port);
      McpConfig config = new McpConfig("127.0.0.1", port, "/mcp", null, "test-mcp", "ghidra");
      try {
        McpHttpServer server =
            new McpHttpServer(config, dispatcher, ignored -> {}, maxSseSessions, sseKeepaliveMillis);
        server.start();
        return new ServerHandle(server, dispatcher, port);
      } catch (BindException retry) {
        dispatcher.close();
      }
    }
    throw new IOException("Unable to bind test MCP HTTP server");
  }

  private static AgentDispatcher newDispatcher(Runnable onSaveProgram, int port) {
    ProgramService programService =
        stub(
            ProgramService.class,
            (method, args) -> {
              if ("getLanguageInfo".equals(method)) {
                onSaveProgram.run();
                return new ProgramLanguageResource(
                    "x86:LE:64:default",
                    "gcc",
                    "x86",
                    ProgramLanguageResource.Endian.LITTLE,
                    64);
              }
              throw new UnsupportedOperationException(method);
            });
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException error) {
              throw error;
            } catch (Exception error) {
              throw new IllegalStateException(error);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            programService,
            stub(AddressService.class),
            stub(CommentService.class),
            stub(ReferenceService.class),
            stub(MemoryService.class),
            stub(ListingService.class),
            stub(FunctionService.class),
            stub(GlobalVariableService.class),
            stub(AnalysisService.class),
            stub(DecompilationService.class),
            stub(SymbolService.class),
            stub(DataTypeService.class),
            transactionRunner,
            "test.bin");
    AgentConfig agentConfig =
        new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "test-mcp", null);
    return new AgentDispatcher(services, agentConfig);
  }

  private static <T> T stub(Class<T> type) {
    return stub(
        type,
        (method, args) -> {
          throw new UnsupportedOperationException(method);
        });
  }

  @SuppressWarnings("unchecked")
  private static <T> T stub(Class<T> type, MethodResponder responder) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "close" -> null;
                  case "toString" -> type.getSimpleName() + "Stub";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == (args == null || args.length == 0 ? null : args[0]);
                  default -> responder.invoke(method.getName(), args);
                });
  }

  private static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static int rawHttpStatus(int port, List<String> requestLines, String body)
      throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5_000);
      OutputStream output = socket.getOutputStream();
      String headerBlock = String.join("\r\n", requestLines) + "\r\n\r\n" + body;
      output.write(headerBlock.getBytes(StandardCharsets.UTF_8));
      output.flush();
      BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
      String statusLine = reader.readLine();
      return Integer.parseInt(statusLine.split(" ", 3)[1]);
    }
  }

  private static RawSseStream openSseStream(int port) throws IOException {
    RawSseStream stream = tryOpenSseStream(port);
    if (stream == null) {
      throw new IOException("SSE stream did not return HTTP 200");
    }
    return stream;
  }

  private static RawSseStream tryOpenSseStream(int port) throws IOException {
    Socket socket = new Socket("127.0.0.1", port);
    socket.setSoTimeout(5_000);
    OutputStream output = socket.getOutputStream();
    String request =
        "GET /mcp HTTP/1.1\r\n"
            + "Host: 127.0.0.1:"
            + port
            + "\r\n"
            + "Accept: text/event-stream\r\n\r\n";
    output.write(request.getBytes(StandardCharsets.US_ASCII));
    output.flush();

    InputStream input = socket.getInputStream();
    String headers = readHeaders(input);
    int status = Integer.parseInt(headers.split("\r\n", 2)[0].split(" ", 3)[1]);
    if (status != 200) {
      socket.close();
      return null;
    }
    BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
    String endpointData = null;
    String line;
    while ((line = reader.readLine()) != null) {
      if (line.startsWith("data: ")) {
        endpointData = line.substring("data: ".length());
      } else if (line.isEmpty() && endpointData != null) {
        break;
      }
    }
    return new RawSseStream(socket, endpointData == null ? "" : endpointData);
  }

  private static String readHeaders(InputStream input) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int state = 0;
    while (state < 4) {
      int b = input.read();
      if (b < 0) {
        break;
      }
      buffer.write(b);
      state =
          switch (state) {
            case 0 -> b == '\r' ? 1 : 0;
            case 1 -> b == '\n' ? 2 : 0;
            case 2 -> b == '\r' ? 3 : 0;
            case 3 -> b == '\n' ? 4 : 0;
            default -> state;
          };
    }
    return buffer.toString(StandardCharsets.US_ASCII);
  }

  @FunctionalInterface
  private interface MethodResponder {
    Object invoke(String method, Object[] args);
  }

  private record RawSseStream(Socket socket, String endpointEvent) implements AutoCloseable {
    @Override
    public void close() throws IOException {
      socket.close();
    }
  }

  private record ServerHandle(McpHttpServer server, AgentDispatcher dispatcher, int port)
      implements AutoCloseable {
    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
  }
}
