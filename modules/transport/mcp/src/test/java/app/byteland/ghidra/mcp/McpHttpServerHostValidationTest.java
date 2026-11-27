package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class McpHttpServerHostValidationTest {

  @Test
  @DisplayName("Rejects GET, POST, OPTIONS, and HEAD with external Host header (403) and zero SSE sessions")
  void rejectsExternalHostAcrossAllHttpMethodsOnLoopback() throws Exception {
    AtomicInteger programGetCalls = new AtomicInteger();
    try (RunningMcpServer running = startServer("127.0.0.1", null, programGetCalls)) {
      int port = running.port();

      // Exact GET /mcp SSE probe from proof harness
      RawHttpResponse getProbe =
          sendRawHttp(
              port,
              "GET /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Accept: text/event-stream\r\n"
                  + "Origin: http://127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Connection: close\r\n\r\n",
              false);
      assertEquals(403, getProbe.status());
      assertNull(getProbe.headers().get("access-control-allow-origin"));
      assertEquals(0, running.server().activeSseSessionCount());

      // Exact POST /mcp probe from proof harness
      String postBody = programGetCallJson();
      RawHttpResponse postProbe =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: tools/call\r\n"
                  + "Mcp-Name: ghidra.program\r\n"
                  + "Content-Length: "
                  + postBody.getBytes(StandardCharsets.UTF_8).length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + postBody,
              false);
      assertEquals(403, postProbe.status());
      assertNull(postProbe.headers().get("access-control-allow-origin"));
      assertEquals(0, programGetCalls.get());

      // Baseline POST /mcp tools/call on 127.0.0.1:<port> succeeds
      RawHttpResponse baselinePost =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: tools/call\r\n"
                  + "Mcp-Name: ghidra.program\r\n"
                  + "Content-Length: "
                  + postBody.getBytes(StandardCharsets.UTF_8).length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + postBody,
              false);
      assertEquals(200, baselinePost.status());
      assertEquals(1, programGetCalls.get());

      // OPTIONS /mcp with external Host
      RawHttpResponse optionsProbe =
          sendRawHttp(
              port,
              "OPTIONS /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Origin: http://127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Connection: close\r\n\r\n",
              false);
      assertEquals(403, optionsProbe.status());
      assertNull(optionsProbe.headers().get("access-control-allow-origin"));

      // HEAD /mcp with external Host
      RawHttpResponse headProbe =
          sendRawHttp(
              port,
              "HEAD /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Connection: close\r\n\r\n",
              true);
      assertEquals(403, headProbe.status());
      assertNull(headProbe.headers().get("access-control-allow-origin"));
      assertEquals(0, running.server().activeSseSessionCount());
    }
  }

  @Test
  @DisplayName("Rejects missing, blank, malformed, and duplicate Host headers with 400")
  void rejectsMalformedMissingBlankAndDuplicateHostHeaders() throws Exception {
    AtomicInteger programGetCalls = new AtomicInteger();
    try (RunningMcpServer running = startServer("127.0.0.1", null, programGetCalls)) {
      int port = running.port();

      // Absent Host header
      RawHttpResponse missing =
          sendRawHttp(port, "GET /mcp HTTP/1.1\r\nConnection: close\r\n\r\n", false);
      assertEquals(400, missing.status());
      assertNull(missing.headers().get("access-control-allow-origin"));

      // Blank Host header
      RawHttpResponse blank =
          sendRawHttp(port, "GET /mcp HTTP/1.1\r\nHost:    \r\nConnection: close\r\n\r\n", false);
      assertEquals(400, blank.status());
      assertNull(blank.headers().get("access-control-allow-origin"));

      // Malformed Host header
      RawHttpResponse malformed =
          sendRawHttp(
              port, "POST /mcp HTTP/1.1\r\nHost: [::1\r\nConnection: close\r\n\r\n", false);
      assertEquals(400, malformed.status());
      assertNull(malformed.headers().get("access-control-allow-origin"));

      // Duplicate Host header
      RawHttpResponse duplicate =
          sendRawHttp(
              port,
              "GET /mcp HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Connection: close\r\n\r\n",
              false);
      assertEquals(400, duplicate.status());
      assertNull(duplicate.headers().get("access-control-allow-origin"));
      assertEquals(0, running.server().activeSseSessionCount());
    }
  }

  @Test
  @DisplayName("Allows 127.0.0.1:<port>, [::1]:<port>, and localhost:<port> on loopback listeners")
  void allowsLoopbackHostsAcrossMethods() throws Exception {
    AtomicInteger programGetCalls = new AtomicInteger();
    try (RunningMcpServer running = startServer("127.0.0.1", null, programGetCalls)) {
      int port = running.port();
      List<String> validHosts =
          List.of("127.0.0.1:" + port, "[::1]:" + port, "localhost:" + port, "LOCALHOST");

      for (String hostHeader : validHosts) {
        String body = pingRequestJson();
        RawHttpResponse post =
            sendRawHttp(
                port,
                "POST /mcp HTTP/1.1\r\n"
                    + "Host: "
                    + hostHeader
                    + "\r\n"
                    + "Content-Type: application/json\r\n"
                    + "MCP-Protocol-Version: 2026-07-28\r\n"
                    + "Mcp-Method: ping\r\n"
                    + "Content-Length: "
                    + body.getBytes(StandardCharsets.UTF_8).length
                    + "\r\n"
                    + "Connection: close\r\n\r\n"
                    + body,
                false);
        assertEquals(200, post.status(), "Expected 200 POST for Host: " + hostHeader);
        assertTrue(post.body().contains("\"resultType\":\"complete\""));

        RawHttpResponse options =
            sendRawHttp(
                port,
                "OPTIONS /mcp HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\n\r\n",
                false);
        assertEquals(204, options.status());

        RawHttpResponse head =
            sendRawHttp(
                port,
                "HEAD /mcp HTTP/1.1\r\nHost: " + hostHeader + "\r\nConnection: close\r\n\r\n",
                true);
        assertEquals(200, head.status());
      }

      // Verify SSE GET succeeds on valid loopback Host
      try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
        socket.setSoTimeout(5_000);
        OutputStream out = socket.getOutputStream();
        out.write(
            ("GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:"
                    + port
                    + "\r\nAccept: text/event-stream\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        String statusLine = reader.readLine();
        assertTrue(statusLine != null && statusLine.startsWith("HTTP/1.1 200"));
        boolean sawEndpointEvent = false;
        String line;
        while ((line = reader.readLine()) != null) {
          if (line.startsWith("event: endpoint")) {
            sawEndpointEvent = true;
            break;
          }
        }
        assertTrue(sawEndpointEvent, "Expected SSE endpoint event on valid loopback Host");
      }
    }
  }

  @Test
  @DisplayName("Authenticated non-loopback listener requires a single well-formed Host and bearer token")
  void authenticatedNonLoopbackListenerRequiresWellFormedHostAndBearerToken() throws Exception {
    AtomicInteger programGetCalls = new AtomicInteger();
    try (RunningMcpServer running = startServer("0.0.0.0", "secret-token-123", programGetCalls)) {
      int port = running.port();
      String body = pingRequestJson();

      // Absent Host -> 400
      RawHttpResponse missingHost =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Authorization: Bearer secret-token-123\r\n"
                  + "Content-Type: application/json\r\n"
                  + "Content-Length: "
                  + body.getBytes(StandardCharsets.UTF_8).length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + body,
              false);
      assertEquals(400, missingHost.status());

      // Well-formed configured proxy Host without token -> 401
      RawHttpResponse missingToken =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: ghidra.corp.example:8443\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: ping\r\n"
                  + "Content-Length: "
                  + body.getBytes(StandardCharsets.UTF_8).length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + body,
              false);
      assertEquals(401, missingToken.status());

      // Well-formed configured proxy Host with valid bearer token -> 200
      RawHttpResponse authorized =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: ghidra.corp.example:8443\r\n"
                  + "Authorization: Bearer secret-token-123\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: ping\r\n"
                  + "Content-Length: "
                  + body.getBytes(StandardCharsets.UTF_8).length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + body,
              false);
      assertEquals(200, authorized.status());
      assertFalse(authorized.body().isBlank());
    }
  }

  private static String pingRequestJson() {
    return "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"_meta\":{"
        + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
        + "\"io.modelcontextprotocol/clientCapabilities\":{}}}}";
  }

  private static String programGetCallJson() {
    return "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"_meta\":{"
        + "\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
        + "\"io.modelcontextprotocol/clientCapabilities\":{}},"
        + "\"name\":\"ghidra.program\",\"arguments\":{\"operation\":\"get\",\"params\":{}}}}";
  }

  private static RawHttpResponse sendRawHttp(int port, String rawRequest, boolean headRequest)
      throws IOException {
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
      socket.setSoTimeout(5_000);
      OutputStream output = socket.getOutputStream();
      output.write(rawRequest.getBytes(StandardCharsets.UTF_8));
      output.flush();

      BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
      String statusLine = reader.readLine();
      if (statusLine == null) {
        throw new IOException("Empty HTTP response");
      }
      String[] parts = statusLine.split(" ", 3);
      int status = Integer.parseInt(parts[1]);
      Map<String, String> headers = new LinkedHashMap<>();
      String line;
      while ((line = reader.readLine()) != null && !line.isEmpty()) {
        int colon = line.indexOf(':');
        if (colon > 0) {
          headers.put(
              line.substring(0, colon).trim().toLowerCase(Locale.ROOT),
              line.substring(colon + 1).trim());
        }
      }
      if (headRequest || status == 204) {
        return new RawHttpResponse(status, headers, "");
      }
      StringBuilder body = new StringBuilder();
      char[] buf = new char[1024];
      int read;
      while ((read = reader.read(buf)) >= 0) {
        body.append(buf, 0, read);
      }
      return new RawHttpResponse(status, headers, body.toString());
    }
  }

  private static RunningMcpServer startServer(
      String host, String token, AtomicInteger programGetCalls) throws IOException {
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = findFreePort();
      AgentDispatcher dispatcher = createStubDispatcher(programGetCalls);
      McpConfig mcpConfig = new McpConfig(host, port, "/mcp", token, "test-session", "ghidra");
      try {
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher);
        server.start();
        return new RunningMcpServer(server, dispatcher, port);
      } catch (BindException retry) {
        dispatcher.close();
      }
    }
    throw new IOException("Unable to bind test McpHttpServer after retries");
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      return socket.getLocalPort();
    }
  }

  private static AgentDispatcher createStubDispatcher(AtomicInteger programGetCalls) {
    ProgramService programService =
        (ProgramService)
            Proxy.newProxyInstance(
                ProgramService.class.getClassLoader(),
                new Class<?>[] {ProgramService.class},
                (proxy, method, args) -> {
                  if ("getProgram".equals(method.getName())) {
                    programGetCalls.incrementAndGet();
                    return new ProgramResource(
                        "test.bin",
                        "/test.bin",
                        "ELF",
                        "ram:00100000",
                        "ram:00100000",
                        "ram:00100fff",
                        "x86:LE:64:default",
                        "gcc",
                        Instant.EPOCH,
                        Instant.EPOCH,
                        1L,
                        1L);
                  }
                  throw new UnsupportedOperationException(method.getName());
                });
    BridgeServices services =
        new BridgeServices(
            programService,
            stubInterface(AddressService.class),
            stubInterface(CommentService.class),
            stubInterface(ReferenceService.class),
            stubInterface(MemoryService.class),
            stubInterface(ListingService.class),
            stubInterface(FunctionService.class),
            stubInterface(GlobalVariableService.class),
            stubCloseable(AnalysisService.class),
            stubCloseable(DecompilationService.class),
            stubInterface(SymbolService.class),
            stubInterface(DataTypeService.class),
            new TransactionRunner() {
              @Override
              public <T> T run(Operation<T> operation) {
                try {
                  return operation.execute();
                } catch (RuntimeException runtime) {
                  throw runtime;
                } catch (Exception checked) {
                  throw new IllegalStateException(checked);
                }
              }
            },
            "test.bin");
    return new AgentDispatcher(services, "test-session");
  }

  @SuppressWarnings("unchecked")
  private static <T> T stubInterface(Class<T> iface) {
    return (T)
        Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[] {iface},
            (proxy, method, args) -> {
              throw new UnsupportedOperationException(method.getName());
            });
  }

  @SuppressWarnings("unchecked")
  private static <T extends AutoCloseable> T stubCloseable(Class<T> iface) {
    return (T)
        Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[] {iface},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              throw new UnsupportedOperationException(method.getName());
            });
  }

  private record RawHttpResponse(int status, Map<String, String> headers, String body) {}

  private record RunningMcpServer(McpHttpServer server, AgentDispatcher dispatcher, int port)
      implements AutoCloseable {
    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
  }
}
