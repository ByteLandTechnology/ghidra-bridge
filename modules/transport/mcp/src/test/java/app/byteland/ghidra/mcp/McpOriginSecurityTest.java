package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class McpOriginSecurityTest {
  private static final String ALLOWED_INSPECTOR_ORIGIN = "http://127.0.0.1:6274";

  @Test
  void configDefaultsToEmptyAllowedOriginsAndNormalizesEntries() {
    McpConfig defaults = McpConfig.fromMap(Map.of());
    assertEquals(Set.of(), defaults.allowedOrigins());

    McpConfig sixArg = new McpConfig("127.0.0.1", 8766, "/mcp", null, "demo", "ghidra");
    assertEquals(Set.of(), sixArg.allowedOrigins());

    McpConfig blankArg = McpConfig.fromMap(Map.of("allowed_origins", "   "));
    assertEquals(Set.of(), blankArg.allowedOrigins());

    McpConfig normalized =
        McpConfig.fromMap(
            Map.of(
                "allowed_origins",
                "HTTP://LocalHost:6274, http://127.0.0.1:80 , http://[::1]:6274"));
    assertEquals(
        Set.of("http://localhost:6274", "http://127.0.0.1", "http://[::1]:6274"),
        normalized.allowedOrigins());

    McpConfig externalWithToken =
        McpConfig.fromMap(
            Map.of(
                "token",
                "secret",
                "allowed_origins",
                "HTTPS://Trusted.Example:443,https://app.trusted.example:8443"));
    assertEquals(
        Set.of("https://trusted.example", "https://app.trusted.example:8443"),
        externalWithToken.allowedOrigins());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "*",
        "http://*",
        "https://*.trusted.example",
        "null",
        "NULL",
        "http://127.0.0.1:6274/",
        "http://127.0.0.1:6274/mcp",
        "http://127.0.0.1:6274?foo=bar",
        "http://127.0.0.1:6274?",
        "http://127.0.0.1:6274#frag",
        "http://127.0.0.1:6274#",
        "ws://127.0.0.1:6274",
        "wss://127.0.0.1:6274",
        "file:///tmp/index.html",
        "chrome-extension://abcdefghijklmnop",
        "ftp://127.0.0.1:21",
        "127.0.0.1:6274",
        "http:127.0.0.1",
        "http://user@127.0.0.1:6274",
        "http://127.0.0.1:",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:080",
        "http://127.0.0.1:abc",
        "http://127.0.0.1:6274,",
        ",http://127.0.0.1:6274",
        ","
      })
  void configRejectsInvalidAllowedOrigins(String invalidOrigin) {
    assertThrows(
        IllegalArgumentException.class,
        () -> McpConfig.fromMap(Map.of("token", "secret", "allowed_origins", invalidOrigin)));
  }

  @Test
  void configRequiresTokenForNonLoopbackAllowedOrigins() {
    assertThrows(
        IllegalArgumentException.class,
        () -> McpConfig.fromMap(Map.of("allowed_origins", "https://trusted.example")));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            McpConfig.fromMap(
                Map.of("allowed_origins", "http://127.0.0.1:6274,https://trusted.example")));
    assertThrows(
        IllegalArgumentException.class,
        () -> McpConfig.fromMap(Map.of("allowed_origins", "http://192.168.1.10:6274")));
    assertThrows(
        IllegalArgumentException.class,
        () -> McpConfig.fromMap(Map.of("allowed_origins", "http://0.0.0.0:6274")));

    Set<String> withNull = new HashSet<>(Collections.singletonList(null));
    assertThrows(
        IllegalArgumentException.class,
        () -> new McpConfig("127.0.0.1", 8766, "/mcp", "secret", "demo", "ghidra", withNull));
  }

  @Test
  void defaultServerRejectsCrossOriginRequestsAndAllowsOriginlessClients() throws Exception {
    AtomicInteger programCalls = new AtomicInteger();
    try (RunningServer running = startServer(Map.of(), programCalls)) {
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
      URI endpoint = URI.create(running.server().endpoint());
      String programGetBody = programGetRequestBody();

      HttpRequest preflightReq =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", "https://untrusted.example")
              .header("Access-Control-Request-Method", "POST")
              .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<String> preflightResp =
          client.send(preflightReq, HttpResponse.BodyHandlers.ofString());
      assertEquals(403, preflightResp.statusCode());
      assertTrue(preflightResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
      assertTrue(preflightResp.headers().firstValue("Vary").isEmpty());

      HttpRequest postReq =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", "https://untrusted.example")
              .header("Content-Type", "application/json")
              .header("MCP-Protocol-Version", "2026-07-28")
              .header("Mcp-Method", "tools/call")
              .header("Mcp-Name", "ghidra_program")
              .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
              .build();
      HttpResponse<String> postResp = client.send(postReq, HttpResponse.BodyHandlers.ofString());
      assertEquals(403, postResp.statusCode());
      assertTrue(postResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
      assertEquals(0, programCalls.get());

      for (String loopbackOrigin : List.of("http://localhost:3000", ALLOWED_INSPECTOR_ORIGIN)) {
        HttpRequest localOriginPost =
            HttpRequest.newBuilder(endpoint)
                .header("Origin", loopbackOrigin)
                .header("Content-Type", "application/json")
                .header("MCP-Protocol-Version", "2026-07-28")
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "ghidra_program")
                .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
                .build();
        HttpResponse<String> localResp =
            client.send(localOriginPost, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, localResp.statusCode());
        assertTrue(localResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
      }

      HttpRequest headWithOrigin =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", "http://localhost:3000")
              .method("HEAD", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<Void> headResp =
          client.send(headWithOrigin, HttpResponse.BodyHandlers.discarding());
      assertEquals(403, headResp.statusCode());
      assertTrue(headResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());

      HttpRequest sseWithOrigin =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", "http://localhost:3000")
              .header("Accept", "text/event-stream")
              .GET()
              .build();
      HttpResponse<String> sseResp =
          client.send(sseWithOrigin, HttpResponse.BodyHandlers.ofString());
      assertEquals(403, sseResp.statusCode());
      assertTrue(sseResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
      assertEquals(0, programCalls.get());

      // CLI and desktop clients omitting Origin succeed without CORS headers.
      HttpRequest cliPost =
          HttpRequest.newBuilder(endpoint)
              .header("Content-Type", "application/json")
              .header("MCP-Protocol-Version", "2026-07-28")
              .header("Mcp-Method", "tools/call")
              .header("Mcp-Name", "ghidra_program")
              .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
              .build();
      HttpResponse<String> cliResp = client.send(cliPost, HttpResponse.BodyHandlers.ofString());
      assertEquals(200, cliResp.statusCode());
      assertTrue(cliResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
      assertTrue(cliResp.headers().firstValue("Vary").isEmpty());
      assertEquals(1, programCalls.get());

      HttpRequest cliHead =
          HttpRequest.newBuilder(endpoint)
              .method("HEAD", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<Void> cliHeadResp = client.send(cliHead, HttpResponse.BodyHandlers.discarding());
      assertEquals(200, cliHeadResp.statusCode());
      assertTrue(cliHeadResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());

      HttpRequest cliOptions =
          HttpRequest.newBuilder(endpoint)
              .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<String> cliOptionsResp =
          client.send(cliOptions, HttpResponse.BodyHandlers.ofString());
      assertEquals(204, cliOptionsResp.statusCode());
      assertTrue(cliOptionsResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    }
  }

  @Test
  void allowlistedOriginSucceedsAcrossHandlersWhileOtherAndMultiValuedOriginsFail()
      throws Exception {
    AtomicInteger programCalls = new AtomicInteger();
    try (RunningServer running =
        startServer(Map.of("allowed_origins", ALLOWED_INSPECTOR_ORIGIN), programCalls)) {
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
      URI endpoint = URI.create(running.server().endpoint());
      String programGetBody = programGetRequestBody();

      // OPTIONS preflight for allowlisted origin
      HttpRequest allowedPreflight =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", ALLOWED_INSPECTOR_ORIGIN)
              .header("Access-Control-Request-Method", "POST")
              .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<String> allowedPreflightResp =
          client.send(allowedPreflight, HttpResponse.BodyHandlers.ofString());
      assertEquals(204, allowedPreflightResp.statusCode());
      assertEquals(
          ALLOWED_INSPECTOR_ORIGIN,
          allowedPreflightResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
      assertEquals(
          "Origin", allowedPreflightResp.headers().firstValue("Vary").orElse(null));
      assertFalse(
          allowedPreflightResp.headers().firstValue("Access-Control-Allow-Methods").isEmpty());

      // HEAD for allowlisted origin
      HttpRequest allowedHead =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", ALLOWED_INSPECTOR_ORIGIN)
              .method("HEAD", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<Void> allowedHeadResp =
          client.send(allowedHead, HttpResponse.BodyHandlers.discarding());
      assertEquals(200, allowedHeadResp.statusCode());
      assertEquals(
          ALLOWED_INSPECTOR_ORIGIN,
          allowedHeadResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
      assertEquals("Origin", allowedHeadResp.headers().firstValue("Vary").orElse(null));

      // POST for allowlisted origin
      HttpRequest allowedPost =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", ALLOWED_INSPECTOR_ORIGIN)
              .header("Content-Type", "application/json")
              .header("MCP-Protocol-Version", "2026-07-28")
              .header("Mcp-Method", "tools/call")
              .header("Mcp-Name", "ghidra_program")
              .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
              .build();
      HttpResponse<String> allowedPostResp =
          client.send(allowedPost, HttpResponse.BodyHandlers.ofString());
      assertEquals(200, allowedPostResp.statusCode());
      assertEquals(
          ALLOWED_INSPECTOR_ORIGIN,
          allowedPostResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
      assertEquals("Origin", allowedPostResp.headers().firstValue("Vary").orElse(null));
      assertEquals(1, programCalls.get());

      // GET SSE for allowlisted origin
      HttpRequest allowedSse =
          HttpRequest.newBuilder(endpoint)
              .header("Origin", ALLOWED_INSPECTOR_ORIGIN)
              .header("Accept", "text/event-stream")
              .GET()
              .build();
      HttpResponse<InputStream> sseStreamResp =
          client.send(allowedSse, HttpResponse.BodyHandlers.ofInputStream());
      assertEquals(200, sseStreamResp.statusCode());
      assertEquals(
          ALLOWED_INSPECTOR_ORIGIN,
          sseStreamResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
      assertEquals("Origin", sseStreamResp.headers().firstValue("Vary").orElse(null));
      try (BufferedReader reader =
          new BufferedReader(
              new InputStreamReader(sseStreamResp.body(), StandardCharsets.UTF_8))) {
        assertEquals("event: endpoint", reader.readLine());
      }

      // Non-matching origins (different host, scheme, port, null, trailing slash, comma-joined)
      for (String disallowed :
          List.of(
              "https://untrusted.example",
              "http://localhost:6274",
              "https://127.0.0.1:6274",
              "http://127.0.0.1:6275",
              "http://127.0.0.1",
              "http://127.0.0.1:6274/",
              "null",
              "*",
              ALLOWED_INSPECTOR_ORIGIN + ", https://untrusted.example")) {
        HttpRequest badPost =
            HttpRequest.newBuilder(endpoint)
                .header("Origin", disallowed)
                .header("Content-Type", "application/json")
                .header("MCP-Protocol-Version", "2026-07-28")
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "ghidra_program")
                .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
                .build();
        HttpResponse<String> badResp = client.send(badPost, HttpResponse.BodyHandlers.ofString());
        assertEquals(403, badResp.statusCode(), "Expected 403 for origin: " + disallowed);
        assertTrue(badResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
        assertTrue(badResp.headers().firstValue("Vary").isEmpty());
      }
      assertEquals(1, programCalls.get());

      // Multi-valued and empty Origin headers on the wire must return 403 without CORS headers.
      String duplicateDifferent =
          sendRawHttp(
              endpoint,
              "OPTIONS "
                  + endpoint.getRawPath()
                  + " HTTP/1.1\r\n"
                  + "Host: "
                  + endpoint.getAuthority()
                  + "\r\n"
                  + "Origin: "
                  + ALLOWED_INSPECTOR_ORIGIN
                  + "\r\n"
                  + "Origin: https://untrusted.example\r\n"
                  + "Connection: close\r\n\r\n");
      assertTrue(duplicateDifferent.startsWith("HTTP/1.1 403"), duplicateDifferent);
      assertFalse(
          duplicateDifferent.toLowerCase().contains("access-control-allow-origin"),
          duplicateDifferent);

      String duplicateSame =
          sendRawHttp(
              endpoint,
              "OPTIONS "
                  + endpoint.getRawPath()
                  + " HTTP/1.1\r\n"
                  + "Host: "
                  + endpoint.getAuthority()
                  + "\r\n"
                  + "Origin: "
                  + ALLOWED_INSPECTOR_ORIGIN
                  + "\r\n"
                  + "Origin: "
                  + ALLOWED_INSPECTOR_ORIGIN
                  + "\r\n"
                  + "Connection: close\r\n\r\n");
      assertTrue(duplicateSame.startsWith("HTTP/1.1 403"), duplicateSame);
      assertFalse(
          duplicateSame.toLowerCase().contains("access-control-allow-origin"), duplicateSame);

      String blankOrigin =
          sendRawHttp(
              endpoint,
              "OPTIONS "
                  + endpoint.getRawPath()
                  + " HTTP/1.1\r\n"
                  + "Host: "
                  + endpoint.getAuthority()
                  + "\r\n"
                  + "Origin: \r\n"
                  + "Connection: close\r\n\r\n");
      assertTrue(blankOrigin.startsWith("HTTP/1.1 403"), blankOrigin);
      assertFalse(
          blankOrigin.toLowerCase().contains("access-control-allow-origin"), blankOrigin);
    }
  }

  private static String sendRawHttp(URI endpoint, String rawRequest) throws IOException {
    try (Socket socket = new Socket(endpoint.getHost(), endpoint.getPort())) {
      socket.setSoTimeout(5000);
      OutputStream out = socket.getOutputStream();
      out.write(rawRequest.getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static String programGetRequestBody() {
    Map<String, Object> meta =
        Map.of(
            "io.modelcontextprotocol/protocolVersion", "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities", Map.of());
    Map<String, Object> params =
        Map.of(
            "_meta", meta,
            "name", "ghidra_program",
            "arguments", Map.of("operation", "get", "params", Map.of()));
    return JsonUtil.toJson(
        Map.of("jsonrpc", "2.0", "id", 1, "method", "tools/call", "params", params));
  }

  private static RunningServer startServer(
      Map<String, String> extraArgs, AtomicInteger programCalls) throws IOException {
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("getProgram".equals(method)) {
                programCalls.incrementAndGet();
                return new ProgramResource(
                    "demo.bin",
                    "/tmp/demo.bin",
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
              throw new AssertionError("Unexpected ProgramService call: " + method);
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
            unused(AnalysisService.class),
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactionRunner,
            "demo.bin");

    IOException lastError = null;
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = allocateLoopbackPort();
      Map<String, String> args = new LinkedHashMap<>(extraArgs);
      args.put("host", "127.0.0.1");
      args.put("port", Integer.toString(port));
      args.put("session_id", "demo-session");
      McpConfig mcpConfig = McpConfig.fromMap(args);
      AgentConfig agentConfig =
          new AgentConfig(
              null,
              mcpConfig.host(),
              mcpConfig.port(),
              mcpConfig.path(),
              mcpConfig.token(),
              mcpConfig.sessionId(),
              null);
      AgentDispatcher dispatcher = new AgentDispatcher(services, agentConfig);
      try {
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher);
        server.start();
        return new RunningServer(server, dispatcher);
      } catch (BindException bindError) {
        dispatcher.close();
        lastError = bindError;
      }
    }
    throw lastError;
  }

  private static int allocateLoopbackPort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
      return socket.getLocalPort();
    }
  }

  private record RunningServer(McpHttpServer server, AgentDispatcher dispatcher)
      implements AutoCloseable {
    @Override
    public void close() {
      try {
        server.close();
      } finally {
        dispatcher.close();
      }
    }
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) {
            return null;
          }
          throw new AssertionError("Unexpected call: " + type.getSimpleName() + "." + method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
