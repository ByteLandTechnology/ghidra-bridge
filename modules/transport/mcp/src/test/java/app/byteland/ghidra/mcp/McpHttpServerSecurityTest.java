package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class McpHttpServerSecurityTest {

  @Test
  @DisplayName("McpConfig requires a non-blank token even for default loopback listeners")
  void mcpConfigRequiresNonBlankToken() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new McpConfig("127.0.0.1", 8766, "/mcp", null, "demo", "ghidra"));
    assertThrows(
        IllegalArgumentException.class,
        () -> new McpConfig("127.0.0.1", 8766, "/mcp", "  ", "demo", "ghidra"));
    assertThrows(IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of()));
  }

  @Test
  @DisplayName("MCP server blocks unauthenticated and DNS-rebound probes while serving authenticated local requests")
  void mcpServerBlocksUnauthenticatedAndRebindProbes() throws Exception {
    int port = findFreePort();
    String token = "mcp-test-secret-token-value";
    AtomicInteger programCalls = new AtomicInteger();
    List<String> requestLogs = Collections.synchronizedList(new ArrayList<>());

    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("getProgram".equals(method)) {
                programCalls.incrementAndGet();
                return new ProgramResource(
                    "fixture.bin",
                    "/fixture.bin",
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
              throw new AssertionError("Unexpected method: " + method);
            });
    BridgeServices services = createServices(programService);
    McpConfig mcpConfig = new McpConfig("127.0.0.1", port, "/mcp", token, "demo", "ghidra");
    AgentConfig agentConfig =
        new AgentConfig(null, "127.0.0.1", port, "/mcp", token, "demo", null);

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, agentConfig);
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher, requestLogs::add)) {
      server.start();

      // 1. Unauthenticated SSE GET probe with DNS rebinding Host -> 401
      HttpReply getRebind =
          sendRawHttp(
              port,
              "GET /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Accept: text/event-stream\r\n"
                  + "Connection: close\r\n\r\n");
      assertEquals(401, getRebind.statusCode());
      assertFalse(getRebind.body().contains(token));

      // 2. Unauthenticated POST tools/call probe with DNS rebinding Host -> 401
      String postBody =
          "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{"
              + "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
              + "\"io.modelcontextprotocol/clientCapabilities\":{}},"
              + "\"name\":\"ghidra.program\",\"arguments\":{\"operation\":\"get\",\"params\":{}}}}";
      byte[] postBytes = postBody.getBytes(StandardCharsets.UTF_8);
      HttpReply postRebind =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: tools/call\r\n"
                  + "Mcp-Name: ghidra_program\r\n"
                  + "Content-Length: "
                  + postBytes.length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + postBody);
      assertEquals(401, postRebind.statusCode());
      assertFalse(postRebind.body().contains(token));

      // 3. Defense-in-depth: even with valid Authorization, rebound Host header is rejected -> 403
      HttpReply authedRebind =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Authorization: Bearer "
                  + token
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: tools/call\r\n"
                  + "Mcp-Name: ghidra.program\r\n"
                  + "Content-Length: "
                  + postBytes.length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + postBody);
      assertEquals(403, authedRebind.statusCode());

      // 4. CORS preflight OPTIONS with rebound Host header -> 403
      HttpReply optionsRebind =
          sendRawHttp(
              port,
              "OPTIONS /mcp HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Connection: close\r\n\r\n");
      assertEquals(403, optionsRebind.statusCode());

      assertEquals(0, programCalls.get(), "No rejected probe may reach AgentDispatcher");

      // 5. Authenticated local SSE GET succeeds with 200 and emits endpoint event
      try (Socket sseSocket = new Socket("127.0.0.1", port)) {
        sseSocket.setSoTimeout(5000);
        OutputStream out = sseSocket.getOutputStream();
        out.write(
            ("GET /mcp HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:"
                    + port
                    + "\r\n"
                    + "Authorization: Bearer "
                    + token
                    + "\r\n"
                    + "Accept: text/event-stream\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(sseSocket.getInputStream(), StandardCharsets.UTF_8));
        String statusLine = reader.readLine();
        assertTrue(statusLine != null && statusLine.startsWith("HTTP/1.1 200"));
      }

      // 6. Authenticated local POST tools/call succeeds with 200
      HttpReply authedLocal =
          sendRawHttp(
              port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Authorization: Bearer "
                  + token
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2026-07-28\r\n"
                  + "Mcp-Method: tools/call\r\n"
                  + "Mcp-Name: ghidra.program\r\n"
                  + "Content-Length: "
                  + postBytes.length
                  + "\r\n"
                  + "Connection: close\r\n\r\n"
                  + postBody);
      assertEquals(200, authedLocal.statusCode());
      assertTrue(authedLocal.body().contains("fixture.bin"));
      assertEquals(1, programCalls.get());

      for (String logLine : requestLogs) {
        assertFalse(logLine.contains(token), "Secret token leaked into request log: " + logLine);
      }
    }
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static HttpReply sendRawHttp(int port, String rawRequest) throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5000);
      OutputStream output = socket.getOutputStream();
      output.write(rawRequest.getBytes(StandardCharsets.UTF_8));
      output.flush();

      String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      int headerEnd = response.indexOf("\r\n\r\n");
      String head = headerEnd >= 0 ? response.substring(0, headerEnd) : response;
      String body = headerEnd >= 0 ? response.substring(headerEnd + 4) : "";
      String statusLine = head.split("\r\n", 2)[0];
      int statusCode = Integer.parseInt(statusLine.split(" ")[1]);
      return new HttpReply(statusCode, head, body);
    }
  }

  private static BridgeServices createServices(ProgramService programService) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) -> {
              if ("close".equals(method)) return null;
              throw new AssertionError(method);
            });
    DecompilationService decomp =
        proxy(
            DecompilationService.class,
            (method, args) -> {
              if ("close".equals(method)) return null;
              throw new AssertionError(method);
            });
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
        programService,
        unused(AddressService.class),
        unused(CommentService.class),
        unused(ReferenceService.class),
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysis,
        decomp,
        unused(SymbolService.class),
        unused(DataTypeService.class),
        tx,
        "fixture.bin");
  }

  private interface Invocation {
    Object handle(String method, Object[] args);
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
            (proxy, method, args) -> invocation.handle(method.getName(), args)));
  }

  private record HttpReply(int statusCode, String headers, String body) {}
}
