package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class McpConfigTest {

  @Test
  @DisplayName("Applies MCP defaults and normalizes path, sessionId, and toolPrefix")
  void appliesDefaultsAndNormalizesFields() {
    McpConfig defaults = McpConfig.fromMap(Map.of());
    assertEquals(InetAddress.getLoopbackAddress().getHostAddress(), defaults.host());
    assertEquals(McpConfig.DEFAULT_PORT, defaults.port());
    assertEquals("/mcp", defaults.path());
    assertNull(defaults.token());
    assertEquals("ghidra-bridge", defaults.sessionId());
    assertEquals(McpConfig.DEFAULT_TOOL_PREFIX, defaults.toolPrefix());
    assertFalse(defaults.portExplicit());

    McpConfig custom =
        McpConfig.fromMap(
            Map.of(
                "host", "127.0.0.1",
                "port", "9001",
                "path", "custom/mcp",
                "token", "  secret-token  ",
                "session_id", "  session-abc  ",
                "tool_prefix", "  custom_ghidra-1  ",
                "jar", "/tmp/ghidra-bridge.jar"));
    assertEquals("127.0.0.1", custom.host());
    assertEquals(9001, custom.port());
    assertEquals("/custom/mcp", custom.path());
    assertEquals("secret-token", custom.token());
    assertEquals("session-abc", custom.sessionId());
    assertEquals("custom_ghidra-1", custom.toolPrefix());
    assertTrue(custom.portExplicit());
    assertEquals("http://127.0.0.1:9001/custom/mcp", custom.endpoint());
  }

  @Test
  @DisplayName("Selects next free loopback port when port is omitted and fails fast when port is explicit")
  void probesSequentialLoopbackPortsWhenOmittedAndFailsWhenExplicit() throws Exception {
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      McpConfig implicitPortConfig =
          new McpConfig("127.0.0.1", busyPort, "/mcp", null, "fallback-mcp", "ghidra", false);
      HttpClient httpClient = HttpClient.newHttpClient();
      try (AgentDispatcher dispatcher =
              new AgentDispatcher(stubServices("second.bin"), implicitPortConfig.sessionId());
          McpHttpServer fallbackServer = new McpHttpServer(implicitPortConfig, dispatcher)) {
        fallbackServer.start();
        assertTrue(
            fallbackServer.port() > busyPort,
            "Expected fallback port above busy port " + busyPort + ", got " + fallbackServer.port());
        assertEquals(
            "http://127.0.0.1:" + fallbackServer.port() + "/mcp", fallbackServer.endpoint());

        Map<String, Object> pingResponse =
            postJsonRpc(
                httpClient,
                fallbackServer.endpoint(),
                Map.of("jsonrpc", "2.0", "id", 1, "method", "ping", "params", Map.of()));
        assertNull(pingResponse.get("error"));
      }

      McpConfig explicitPortConfig =
          McpConfig.fromMap(
              Map.of(
                  "host", "127.0.0.1",
                  "port", Integer.toString(busyPort),
                  "session_id", "explicit-mcp"));
      assertTrue(explicitPortConfig.portExplicit());
      try (AgentDispatcher dispatcher =
          new AgentDispatcher(stubServices("conflict.bin"), explicitPortConfig.sessionId())) {
        assertThrows(BindException.class, () -> new McpHttpServer(explicitPortConfig, dispatcher));
      }
    }
  }

  @Test
  @DisplayName("Validates port, tool_prefix, unknown keys, and non-loopback token requirement")
  void validatesArgumentsAndNonLoopbackTokenRequirement() {
    assertThrows(IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of("port", "0")));
    assertThrows(IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of("port", "65536")));
    assertThrows(IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of("port", "abc")));
    assertThrows(
        IllegalArgumentException.class,
        () -> McpConfig.fromMap(Map.of("ws_url", "ws://127.0.0.1:8765/ws/agent")));
    assertThrows(
        IllegalArgumentException.class,
        () -> McpConfig.fromMap(Map.of("tool_prefix", "ghidra.bad")));
    assertThrows(
        IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of("tool_prefix", "1ghidra")));

    String externalHost = "external.validation.mcp-test.internal";
    assertThrows(
        IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of("host", externalHost)));
    assertEquals(1, CountingInetAddressResolverProvider.lookupCount(externalHost));

    String externalAuthedHost = "external.authed.mcp-test.internal";
    McpConfig authed = McpConfig.fromMap(Map.of("host", externalAuthedHost, "token", "secret"));
    assertEquals(externalAuthedHost, authed.host());
    assertEquals(1, CountingInetAddressResolverProvider.lookupCount(externalAuthedHost));

    String unresolvableHost = "unresolvable.host.mcp-test.internal";
    assertThrows(
        IllegalArgumentException.class, () -> McpConfig.fromMap(Map.of("host", unresolvableHost)));
    assertEquals(1, CountingInetAddressResolverProvider.lookupCount(unresolvableHost));
  }

  @Test
  @DisplayName("Executes NetworkBinding DNS validation once across McpConfig and AgentDispatcher")
  void validatesHostOnceDuringMcpDispatcherStartupWithUncachedDns() throws Exception {
    String javaBin =
        ProcessHandle.current()
            .info()
            .command()
            .orElseGet(() -> Path.of(System.getProperty("java.home"), "bin", "java").toString());
    Process process =
        new ProcessBuilder(
                javaBin,
                "-Dsun.net.inetaddr.ttl=0",
                "-cp",
                System.getProperty("java.class.path"),
                SinglePassProbe.class.getName())
            .redirectErrorStream(true)
            .start();

    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    boolean finished = process.waitFor(15, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
      throw new AssertionError("SinglePassProbe timed out; output: " + output);
    }
    assertEquals(0, process.exitValue(), "SinglePassProbe failed: " + output);
    assertEquals("LOOKUPS=1 SESSION=probe-session", output.trim());
  }

  @Test
  @DisplayName("Serves MCP session ID through AgentDispatcher(BridgeServices, String)")
  void servesSessionIdThroughMcpHttpServer() throws Exception {
    int port = findFreePort();
    McpConfig config =
        McpConfig.fromMap(
            Map.of(
                "host", "127.0.0.1",
                "port", Integer.toString(port),
                "path", "/mcp-test",
                "session_id", "mcp-http-session",
                "tool_prefix", "custom"));

    HttpClient httpClient = HttpClient.newHttpClient();
    try (AgentDispatcher dispatcher = new AgentDispatcher(stubServices("firmware.bin"), config.sessionId());
        McpHttpServer server = new McpHttpServer(config, dispatcher)) {
      server.start();

      Map<String, Object> initializeResponse =
          postJsonRpc(
              httpClient,
              config.endpoint(),
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  1,
                  "method",
                  "initialize",
                  "params",
                  Map.of(
                      "protocolVersion",
                      "2025-11-25",
                      "capabilities",
                      Map.of(),
                      "clientInfo",
                      Map.of("name", "mcp-config-test", "version", "1.0"))));
      assertNull(initializeResponse.get("error"));

      Map<String, Object> callResponse =
          postJsonRpc(
              httpClient,
              config.endpoint(),
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  2,
                  "method",
                  "tools/call",
                  "params",
                  Map.of(
                      "name",
                      "custom_bridge",
                      "arguments",
                      Map.of("operation", "get", "params", Map.of()))));
      @SuppressWarnings("unchecked")
      Map<String, Object> toolResult = (Map<String, Object>) callResponse.get("result");
      assertEquals(Boolean.FALSE, toolResult.get("isError"));
      @SuppressWarnings("unchecked")
      Map<String, Object> structured =
          (Map<String, Object>) toolResult.get("structuredContent");
      @SuppressWarnings("unchecked")
      Map<String, Object> session = (Map<String, Object>) structured.get("result");
      assertEquals("mcp-http-session", session.get("id"));
      assertEquals("active", session.get("status"));
      assertEquals("firmware.bin", session.get("program_name"));
    }
  }

  public static final class SinglePassProbe {
    public static void main(String[] args) throws Exception {
      String host = "loopback.single-pass.mcp-test.internal";
      McpConfig mcpConfig =
          McpConfig.fromMap(
              Map.of("host", host, "port", "8766", "path", "/mcp", "session_id", "probe-session"));
      try (AgentDispatcher dispatcher =
          new AgentDispatcher(stubServices("probe.bin"), mcpConfig.sessionId())) {
        @SuppressWarnings("unchecked")
        Map<String, Object> session =
            (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
        int lookups = CountingInetAddressResolverProvider.lookupCount(host);
        System.out.println("LOOKUPS=" + lookups + " SESSION=" + session.get("id"));
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> postJsonRpc(
      HttpClient client, String endpoint, Map<String, Object> payload)
      throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(payload)))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    return (Map<String, Object>) JsonUtil.parse(response.body());
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  static BridgeServices stubServices(String programName) {
    AnalysisService analysis = closeableStub(AnalysisService.class);
    DecompilationService decompilation = closeableStub(DecompilationService.class);
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("Unexpected transaction");
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
        analysis,
        decompilation,
        unused(SymbolService.class),
        unused(DataTypeService.class),
        transactionRunner,
        programName);
  }

  private static <T> T closeableStub(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              throw new AssertionError("Unexpected call: " + method.getName());
            }));
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError("Unexpected call: " + method.getName());
            }));
  }
}
