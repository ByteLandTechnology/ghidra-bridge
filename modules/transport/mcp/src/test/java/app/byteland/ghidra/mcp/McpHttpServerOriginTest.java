package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class McpHttpServerOriginTest {
  private final AtomicInteger programGetCalls = new AtomicInteger();
  private final List<String> requestLogs = new ArrayList<>();
  private AgentDispatcher dispatcher;
  private McpHttpServer server;
  private URI endpoint;
  private HttpClient client;
  private String programGetBody;

  @BeforeEach
  void setUp() throws IOException {
    programGetCalls.set(0);
    requestLogs.clear();
    dispatcher = createTestDispatcher(programGetCalls);
    server = startServerOnLoopback(dispatcher, requestLogs);
    endpoint = URI.create(server.endpoint());
    client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    programGetBody =
        JsonUtil.toJson(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                1,
                "method",
                "tools/call",
                "params",
                Map.of(
                    "_meta",
                    Map.of(
                        "io.modelcontextprotocol/protocolVersion",
                        "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities",
                        Map.of()),
                    "name",
                    "ghidra_program",
                    "arguments",
                    Map.of("operation", "get", "params", Map.of()))));
  }

  @AfterEach
  void tearDown() {
    if (server != null) {
      server.close();
    }
    if (dispatcher != null) {
      dispatcher.close();
    }
  }

  @Test
  void rejectsUntrustedCrossOriginPreflightAndToolCallWithoutCorsHeaders() throws Exception {
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
    assertNoCorsHeaders(preflightResp);
    assertEquals("Forbidden origin", preflightResp.body());

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
    assertNoCorsHeaders(postResp);
    assertEquals("Forbidden origin", postResp.body());
    assertEquals(0, programGetCalls.get());
  }

  @Test
  void rejectsCrossOriginGetSseAndHeadRequestsWithoutCorsHeaders() throws Exception {
    HttpRequest getReq =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", "https://untrusted.example")
            .header("Accept", "text/event-stream")
            .GET()
            .build();
    HttpResponse<String> getResp = client.send(getReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(403, getResp.statusCode());
    assertNoCorsHeaders(getResp);
    assertEquals("Forbidden origin", getResp.body());

    HttpRequest headReq =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", "https://untrusted.example")
            .method("HEAD", HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> headResp = client.send(headReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(403, headResp.statusCode());
    assertNoCorsHeaders(headResp);
    assertEquals("", headResp.body());
    assertTrue(
        requestLogs.stream().noneMatch(entry -> entry.contains("status=500")),
        () -> "Unexpected 500 log entry: " + requestLogs);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https://untrusted.example",
        "null",
        "NULL",
        "   ",
        "http://127.0.0.1.evil.example",
        "http://localhost.evil.example",
        "http://sub.localhost:3000",
        "http://localhost:3000, https://untrusted.example",
        "http://localhost:3000, http://127.0.0.1:8766",
        "http://user@localhost:8766",
        "http://localhost@untrusted.example",
        "http://@localhost:8766",
        "http://localhost:3000/",
        "http://localhost:3000/mcp",
        "http://localhost:3000?token=abc",
        "http://localhost:3000?",
        "http://localhost:3000#frag",
        "http://localhost:3000#",
        "ws://localhost:8766",
        "wss://localhost:8766",
        "file:///tmp/test",
        "ftp://localhost:21",
        "http:localhost",
        "http://localhost:",
        "http://localhost:0",
        "http://localhost:70000",
        "http://192.168.1.10:8766",
        "http://0.0.0.0:8766",
        "http://[::]:8766",
        "http://[fe80::1]:8766"
      })
  void rejectsDisallowedAndMalformedOrigins(String badOrigin) throws Exception {
    HttpRequest postReq =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", badOrigin)
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "ghidra_program")
            .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
            .build();
    HttpResponse<String> resp = client.send(postReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(403, resp.statusCode(), "Expected 403 for Origin: " + badOrigin);
    assertNoCorsHeaders(resp);
    assertEquals(0, programGetCalls.get());
  }

  @Test
  void rejectsMultipleOriginHeaderLines() throws Exception {
    HttpRequest twoOriginsMixed =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", "http://127.0.0.1:8766")
            .header("Origin", "https://untrusted.example")
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "ghidra_program")
            .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
            .build();
    HttpResponse<String> mixedResp =
        client.send(twoOriginsMixed, HttpResponse.BodyHandlers.ofString());
    assertEquals(403, mixedResp.statusCode());
    assertNoCorsHeaders(mixedResp);

    HttpRequest twoOriginsLoopback =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", "http://localhost:3000")
            .header("Origin", "http://127.0.0.1:8766")
            .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> loopbackResp =
        client.send(twoOriginsLoopback, HttpResponse.BodyHandlers.ofString());
    assertEquals(403, loopbackResp.statusCode());
    assertNoCorsHeaders(loopbackResp);
    assertEquals(0, programGetCalls.get());
  }

  @Test
  void allowsRequestsWithoutOriginAndDoesNotEmitWildcardAllowOrigin() throws Exception {
    HttpRequest postReq =
        HttpRequest.newBuilder(endpoint)
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "ghidra_program")
            .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
            .build();
    HttpResponse<String> postResp = client.send(postReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, postResp.statusCode());
    assertTrue(postResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    assertEquals(1, programGetCalls.get());
    assertTrue(postResp.body().contains("sample.bin"));

    HttpRequest headReq =
        HttpRequest.newBuilder(endpoint)
            .method("HEAD", HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> headResp = client.send(headReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, headResp.statusCode());
    assertTrue(headResp.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://127.0.0.1:8766",
        "https://127.0.0.1:8443",
        "http://127.0.0.2:9000",
        "http://localhost:3000",
        "https://LOCALHOST:3000",
        "http://localhost",
        "http://[::1]:8766",
        "https://[::1]",
        "http://[0:0:0:0:0:0:0:1]:8766",
        "http://[::ffff:127.0.0.1]:8766"
      })
  void allowsLoopbackOriginsAcrossPreflightPostAndSse(String allowedOrigin) throws Exception {
    HttpRequest preflightReq =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", allowedOrigin)
            .header("Access-Control-Request-Method", "POST")
            .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
            .build();
    HttpResponse<String> preflightResp =
        client.send(preflightReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(204, preflightResp.statusCode());
    assertEquals(
        allowedOrigin,
        preflightResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
    assertEquals("Origin", preflightResp.headers().firstValue("Vary").orElse(null));

    HttpRequest postReq =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", allowedOrigin)
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "ghidra_program")
            .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
            .build();
    HttpResponse<String> postResp = client.send(postReq, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, postResp.statusCode());
    assertEquals(
        allowedOrigin, postResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
    assertEquals("Origin", postResp.headers().firstValue("Vary").orElse(null));
  }

  @Test
  void allowsLoopbackGetSseStreamWithValidatedOrigin() throws Exception {
    HttpRequest getReq =
        HttpRequest.newBuilder(endpoint)
            .header("Origin", "http://localhost:3000")
            .header("Accept", "text/event-stream")
            .GET()
            .build();
    HttpResponse<InputStream> resp = client.send(getReq, HttpResponse.BodyHandlers.ofInputStream());
    try (InputStream body = resp.body();
        BufferedReader reader =
            new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8))) {
      assertEquals(200, resp.statusCode());
      assertEquals(
          "http://localhost:3000",
          resp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
      String eventLine = reader.readLine();
      assertEquals("event: endpoint", eventLine);
    }
  }

  @Test
  void matchesConfiguredHostCaseInsensitivelyAndAcrossIpv6RepresentationsWithoutDns() {
    // Hostname match without DNS resolution (.invalid is RFC 2606 guaranteed non-resolvable)
    assertTrue(
        McpHttpServer.isAllowedOrigin(
            List.of("https://GHIDRA-HOST.INVALID:8443"), "ghidra-host.invalid"));
    assertFalse(
        McpHttpServer.isAllowedOrigin(
            List.of("https://other-host.invalid:8443"), "ghidra-host.invalid"));
    assertFalse(
        McpHttpServer.isAllowedOrigin(
            List.of("https://untrusted.invalid"), "127.0.0.1"));

    // Configured non-loopback IPv4 and IPv6 literal match
    assertTrue(
        McpHttpServer.isAllowedOrigin(List.of("http://192.168.1.50:8766"), "192.168.1.50"));
    assertFalse(
        McpHttpServer.isAllowedOrigin(List.of("http://192.168.1.51:8766"), "192.168.1.50"));
    assertTrue(
        McpHttpServer.isAllowedOrigin(List.of("http://[fd00::1]:8766"), "[FD00::1]"));
    assertTrue(
        McpHttpServer.isAllowedOrigin(
            List.of("http://[fd00:0:0:0:0:0:0:1]:8766"), "fd00::1"));
    assertFalse(
        McpHttpServer.isAllowedOrigin(List.of("http://[fd00::2]:8766"), "fd00::1"));

    // Malformed IP literals return null without an exception or DNS query
    assertNull(McpHttpServer.parseIpLiteral("127.0.0.1.evil.example"));
    assertNull(McpHttpServer.parseIpLiteral("127.0.0.01"));
    assertNull(McpHttpServer.parseIpLiteral("127.1"));
    assertNull(McpHttpServer.parseIpLiteral(":::1"));
    assertNull(McpHttpServer.parseIpLiteral("::1%lo0"));
  }

  @Test
  void allowsConfiguredNonLoopbackHostOriginOnLiveServerAndRejectsOtherNonLoopbackOrigins()
      throws Exception {
    String nonLoopbackHost = findLocalNonLoopbackIpv4();
    org.junit.jupiter.api.Assumptions.assumeTrue(
        nonLoopbackHost != null, "No non-loopback IPv4 interface available");

    int customPort;
    try (ServerSocket probe =
        new ServerSocket(0, 1, InetAddress.getByName(nonLoopbackHost))) {
      customPort = probe.getLocalPort();
    }
    McpConfig customConfig =
        new McpConfig(
            nonLoopbackHost, customPort, "/mcp", "secret-token", "custom-session", "ghidra");
    try (McpHttpServer customServer = new McpHttpServer(customConfig, dispatcher)) {
      customServer.start();
      URI customEndpoint = URI.create(customServer.endpoint());
      String matchingOrigin = "http://" + nonLoopbackHost + ":" + customPort;

      HttpRequest allowedPreflight =
          HttpRequest.newBuilder(customEndpoint)
              .header("Origin", matchingOrigin)
              .header("Access-Control-Request-Method", "POST")
              .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
              .build();
      HttpResponse<String> preflightResp =
          client.send(allowedPreflight, HttpResponse.BodyHandlers.ofString());
      assertEquals(204, preflightResp.statusCode());
      assertEquals(
          matchingOrigin,
          preflightResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));

      HttpRequest allowedPost =
          HttpRequest.newBuilder(customEndpoint)
              .header("Origin", matchingOrigin)
              .header("Authorization", "Bearer secret-token")
              .header("Content-Type", "application/json")
              .header("MCP-Protocol-Version", "2026-07-28")
              .header("Mcp-Method", "tools/call")
              .header("Mcp-Name", "ghidra_program")
              .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
              .build();
      HttpResponse<String> postResp =
          client.send(allowedPost, HttpResponse.BodyHandlers.ofString());
      assertEquals(200, postResp.statusCode());
      assertEquals(
          matchingOrigin,
          postResp.headers().firstValue("Access-Control-Allow-Origin").orElse(null));

      HttpRequest untrustedPostWithToken =
          HttpRequest.newBuilder(customEndpoint)
              .header("Origin", "https://untrusted.example")
              .header("Authorization", "Bearer secret-token")
              .header("Content-Type", "application/json")
              .header("MCP-Protocol-Version", "2026-07-28")
              .header("Mcp-Method", "tools/call")
              .header("Mcp-Name", "ghidra_program")
              .POST(HttpRequest.BodyPublishers.ofString(programGetBody))
              .build();
      HttpResponse<String> untrustedResp =
          client.send(untrustedPostWithToken, HttpResponse.BodyHandlers.ofString());
      assertEquals(403, untrustedResp.statusCode());
      assertNoCorsHeaders(untrustedResp);
    }
  }

  private static String findLocalNonLoopbackIpv4() throws IOException {
    var interfaces = java.net.NetworkInterface.getNetworkInterfaces();
    while (interfaces.hasMoreElements()) {
      java.net.NetworkInterface iface = interfaces.nextElement();
      if (!iface.isUp() || iface.isLoopback()) {
        continue;
      }
      var addresses = iface.getInetAddresses();
      while (addresses.hasMoreElements()) {
        InetAddress addr = addresses.nextElement();
        if (addr instanceof java.net.Inet4Address && !addr.isLoopbackAddress()) {
          return addr.getHostAddress();
        }
      }
    }
    return null;
  }

  private static void assertNoCorsHeaders(HttpResponse<?> response) {
    assertTrue(response.headers().firstValue("Access-Control-Allow-Origin").isEmpty());
    assertTrue(response.headers().firstValue("Access-Control-Allow-Methods").isEmpty());
    assertTrue(response.headers().firstValue("Access-Control-Allow-Headers").isEmpty());
    assertTrue(response.headers().firstValue("Access-Control-Expose-Headers").isEmpty());
  }

  private static McpHttpServer startServerOnLoopback(
      AgentDispatcher dispatcher, List<String> requestLogs) throws IOException {
    IOException lastError = null;
    for (int attempt = 0; attempt < 5; attempt++) {
      int port;
      try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
        port = probe.getLocalPort();
      }
      McpConfig config = new McpConfig("127.0.0.1", port, "/mcp", null, "test-session", "ghidra");
      try {
        McpHttpServer candidate = new McpHttpServer(config, dispatcher, requestLogs::add);
        candidate.start();
        return candidate;
      } catch (BindException bindError) {
        lastError = bindError;
      }
    }
    throw lastError;
  }

  private static AgentDispatcher createTestDispatcher(AtomicInteger programGetCalls) {
    ProgramService programs =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("getProgram".equals(method)) {
                programGetCalls.incrementAndGet();
                return new ProgramResource(
                    "sample.bin",
                    "/tmp/sample.bin",
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
    TransactionRunner transactions =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception error) {
              throw new RuntimeException(error);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            programs,
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
            transactions,
            "sample.bin");
    return new AgentDispatcher(services, "test-session");
  }

  private interface Invocation {
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

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxyInstance, method, args) -> invocation.invoke(method.getName(), args)));
  }
}
