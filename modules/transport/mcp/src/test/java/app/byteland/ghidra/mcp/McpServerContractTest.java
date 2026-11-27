package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
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
import java.io.BufferedReader;
import java.io.IOException;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class McpServerContractTest {
  private static final Set<String> FORBIDDEN_KEYS =
      Set.of("oneOf", "anyOf", "allOf", "$ref", "$defs");

  @Test
  @SuppressWarnings("unchecked")
  void toolsListPublishesCompactSchemasDerivedEffectsAndDataUnits() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    List<Map<String, Object>> tools = registry.listTools();
    assertEquals(15, tools.size());

    for (Map<String, Object> tool : tools) {
      String name = (String) tool.get("name");
      assertTrue(name.startsWith("ghidra_"), name);
      assertFalse(name.contains("."), name);
      Map<String, Object> schema = (Map<String, Object>) tool.get("inputSchema");
      assertEquals(Boolean.FALSE, schema.get("additionalProperties"), name);
      assertNoForbiddenKeys(name, schema);

      if (!"ghidra_help".equals(name)) {
        Map<String, Object> props = (Map<String, Object>) schema.get("properties");
        Map<String, Object> params = (Map<String, Object>) props.get("params");
        assertEquals(Boolean.FALSE, params.get("additionalProperties"), name);
        Map<String, Object> paramProps = (Map<String, Object>) params.get("properties");
        assertFalse(paramProps.isEmpty(), "empty params.properties on " + name);
      }
    }

    Map<String, Object> listing = toolByName(tools, "ghidra_listing");
    assertTrue(((String) listing.get("description")).contains("data units"));

    Map<String, Object> decompilation = toolByName(tools, "ghidra_decompilation");
    assertEquals(
        Map.of(
            "readOnlyHint", true,
            "destructiveHint", false,
            "idempotentHint", true,
            "openWorldHint", false),
        decompilation.get("annotations"));
    Map<String, Object> decompParams = paramsSchema(decompilation);
    assertEquals(List.of("selector"), decompParams.get("required"));
    assertTrue(((Map<?, ?>) decompParams.get("properties")).containsKey("format"));

    Map<String, Object> reference = toolByName(tools, "ghidra_reference");
    assertEquals(List.of("filter"), paramsSchema(reference).get("required"));
    assertEquals(Boolean.TRUE, ((Map<?, ?>) reference.get("annotations")).get("readOnlyHint"));

    Map<String, Object> batch = toolByName(tools, "ghidra_batch");
    assertEquals(List.of("items"), paramsSchema(batch).get("required"));

    Map<String, Object> program = toolByName(tools, "ghidra_program");
    assertEquals(
        Map.of(
            "readOnlyHint", false,
            "destructiveHint", false,
            "idempotentHint", false,
            "openWorldHint", false),
        program.get("annotations"));

    Map<String, Object> analysis = toolByName(tools, "ghidra_analysis");
    assertEquals(
        Map.of(
            "readOnlyHint", false,
            "destructiveHint", false,
            "idempotentHint", false,
            "openWorldHint", false),
        analysis.get("annotations"));

    Map<String, Object> function = toolByName(tools, "ghidra_function");
    assertEquals(
        Map.of(
            "readOnlyHint", false,
            "destructiveHint", true,
            "idempotentHint", false,
            "openWorldHint", false),
        function.get("annotations"));
    Map<?, ?> functionParamProps = (Map<?, ?>) paramsSchema(function).get("properties");
    assertTrue(functionParamProps.containsKey("selector"));
    assertTrue(functionParamProps.containsKey("patch"));
    assertTrue(functionParamProps.containsKey("resource"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void domainOnlyHelpReturnsDescriptionsEffectsAndInputSchemas() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog(), "sample");
    Map<String, Object> domainHelp = registry.help(Map.of("domain", "memory"));
    assertEquals("sample_memory", domainHelp.get("domain"));

    List<Map<String, Object>> operations =
        (List<Map<String, Object>>) domainHelp.get("operations");
    assertEquals(4, operations.size());
    for (Map<String, Object> operation : operations) {
      assertNotNull(operation.get("name"));
      assertNotNull(operation.get("method"));
      assertTrue(operation.get("description") instanceof String text && !text.isBlank());
      assertTrue(operation.get("effects") instanceof Map<?, ?> effects && !effects.isEmpty());
      assertTrue(
          operation.get("inputSchema") instanceof Map<?, ?> inputSchema
              && "object".equals(inputSchema.get("type")));
    }

    Map<String, Object> readHelp =
        operations.stream()
            .filter(item -> "read".equals(item.get("name")))
            .findFirst()
            .orElseThrow();
    assertEquals("memory.read", readHelp.get("method"));
    assertEquals(Boolean.TRUE, ((Map<?, ?>) readHelp.get("effects")).get("read_only"));
    assertTrue(
        ((Map<?, ?>) ((Map<?, ?>) readHelp.get("inputSchema")).get("properties"))
            .containsKey("selector"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void mcpHttpServerScopesResourceUrisSupportsSseAndKeepsDottedCallFallback() throws Exception {
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    try (RunningServer defaultRunning = startServer("default-session", "ghidra");
        RunningServer customRunning = startServer("sample-session", "sample")) {
      McpHttpServer defaultServer = defaultRunning.server();
      McpHttpServer customServer = customRunning.server();

      Map<String, Object> defaultList =
          postInitializedJsonRpc(client, defaultServer.endpoint(), "resources/list", Map.of());
      Map<String, Object> customList =
          postInitializedJsonRpc(client, customServer.endpoint(), "resources/list", Map.of());

      String defaultUri = firstResourceUri(defaultList);
      String customUri = firstResourceUri(customList);
      assertEquals("ghidra-bridge://ghidra/contracts/mcp-tools", defaultUri);
      assertEquals("ghidra-bridge://sample/contracts/mcp-tools", customUri);
      assertNotEquals(defaultUri, customUri);

      Map<String, Object> readScopedDefault =
          postInitializedJsonRpc(
              client, defaultServer.endpoint(), "resources/read", Map.of("uri", defaultUri));
      assertNotNull(readScopedDefault.get("result"));

      Map<String, Object> readLegacyDefault =
          postInitializedJsonRpc(
              client,
              defaultServer.endpoint(),
              "resources/read",
              Map.of("uri", "ghidra-bridge://contracts/mcp-tools"));
      assertNotNull(readLegacyDefault.get("result"));

      Map<String, Object> readScopedCustom =
          postInitializedJsonRpc(
              client, customServer.endpoint(), "resources/read", Map.of("uri", customUri));
      assertNotNull(readScopedCustom.get("result"));

      HttpResponse<String> rejectedLegacyOnCustom =
          sendInitializedRaw(
              client,
              customServer.endpoint(),
              "resources/read",
              Map.of("uri", "ghidra-bridge://contracts/mcp-tools"));
      assertEquals(404, rejectedLegacyOnCustom.statusCode());

      Map<String, Object> underscoreCall =
          postInitializedJsonRpc(
              client,
              defaultServer.endpoint(),
              "tools/call",
              Map.of(
                  "name", "ghidra_bridge",
                  "arguments", Map.of("operation", "get", "params", Map.of())));
      Map<String, Object> underscoreResult = (Map<String, Object>) underscoreCall.get("result");
      assertEquals(Boolean.FALSE, underscoreResult.get("isError"));

      Map<String, Object> dottedFallbackCall =
          postInitializedJsonRpc(
              client,
              defaultServer.endpoint(),
              "tools/call",
              Map.of(
                  "name", "ghidra.bridge",
                  "arguments", Map.of("operation", "get", "params", Map.of())));
      Map<String, Object> dottedResult = (Map<String, Object>) dottedFallbackCall.get("result");
      assertEquals(Boolean.FALSE, dottedResult.get("isError"));

      HttpRequest sseRequest =
          HttpRequest.newBuilder(URI.create(defaultServer.endpoint()))
              .header("Accept", "text/event-stream")
              .GET()
              .build();
      HttpResponse<java.io.InputStream> sseResponse =
          client.send(sseRequest, HttpResponse.BodyHandlers.ofInputStream());
      assertEquals(200, sseResponse.statusCode());
      assertTrue(
          sseResponse
              .headers()
              .firstValue("Content-Type")
              .orElse("")
              .startsWith("text/event-stream"));
      try (BufferedReader reader =
          new BufferedReader(new InputStreamReader(sseResponse.body(), StandardCharsets.UTF_8))) {
        String eventLine = reader.readLine();
        String dataLine = reader.readLine();
        assertEquals("event: endpoint", eventLine);
        assertNotNull(dataLine);
        assertTrue(dataLine.startsWith("data: /mcp?sessionId="), dataLine);

        String relativeEndpoint = dataLine.substring("data: ".length());
        String sessionUrl = "http://127.0.0.1:" + defaultRunning.port() + relativeEndpoint;
        HttpResponse<String> posted =
            sendInitializedRaw(client, sessionUrl, "ping", Map.of());
        assertEquals(202, posted.statusCode());

        String blankLine = reader.readLine();
        String msgEvent = reader.readLine();
        String msgData = reader.readLine();
        assertEquals("", blankLine);
        assertEquals("event: message", msgEvent);
        assertTrue(msgData != null && msgData.contains("\"result\":{}"), msgData);
      }
    }
  }

  @Test
  void documentationVerificationRejectsDottedMcpNamesAndStaleGet405Claims(@TempDir Path root)
      throws Exception {
    McpContractGenerator.main(new String[] {root.toString()});
    List<String> guides =
        List.of(
            "README.md",
            "README.zh-CN.md",
            "README.ja-JP.md",
            "docs/protocol.md",
            "docs/zh/protocol.md",
            "docs/ja/protocol.md",
            "docs/architecture.md",
            "docs/zh/architecture.md",
            "docs/ja/architecture.md");
    for (String guide : guides) {
      Path path = root.resolve(guide);
      Files.createDirectories(path.getParent());
      Files.writeString(
          path,
          "Use `ghidra_program` and WebSocket `program.get` or `ghidra.ready`.\n",
          StandardCharsets.UTF_8);
    }
    Path javaFile =
        root.resolve("modules/transport/mcp/src/main/java/app/byteland/ghidra/mcp/McpConfig.java");
    Files.createDirectories(javaFile.getParent());
    Files.writeString(
        javaFile,
        "/** Example tool is {@code ghidra_program}. */\nfinal class Sample {}\n",
        StandardCharsets.UTF_8);

    McpContractGenerator.verifyRepository(root);

    Files.writeString(
        root.resolve("README.md"), "Bad reference `ghidra.program`.\n", StandardCharsets.UTF_8);
    assertThrows(IllegalStateException.class, () -> McpContractGenerator.verifyRepository(root));

    Files.writeString(
        root.resolve("README.md"), "Valid `ghidra_program`.\n", StandardCharsets.UTF_8);
    Files.writeString(
        root.resolve("docs/protocol.md"),
        "- **GET**: The server returns status `405` with `Allow: POST, OPTIONS`.\n",
        StandardCharsets.UTF_8);
    assertThrows(IllegalStateException.class, () -> McpContractGenerator.verifyRepository(root));

    Files.writeString(
        root.resolve("docs/protocol.md"),
        "- **GET**: Opens an SSE stream.\n",
        StandardCharsets.UTF_8);
    Files.writeString(
        javaFile,
        "/** Stale Javadoc {@code ghidra.program}. */\nfinal class Sample {}\n",
        StandardCharsets.UTF_8);
    assertThrows(IllegalStateException.class, () -> McpContractGenerator.verifyRepository(root));
  }

  private static void assertNoForbiddenKeys(String toolName, Object value) {
    if (value instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        String key = String.valueOf(entry.getKey());
        assertFalse(FORBIDDEN_KEYS.contains(key), toolName + " has forbidden key " + key);
        assertNoForbiddenKeys(toolName, entry.getValue());
      }
    } else if (value instanceof List<?> list) {
      for (Object item : list) {
        assertNoForbiddenKeys(toolName, item);
      }
    }
  }

  private static Map<String, Object> toolByName(List<Map<String, Object>> tools, String name) {
    return tools.stream()
        .filter(tool -> name.equals(tool.get("name")))
        .findFirst()
        .orElseThrow(() -> new AssertionError("Missing tool: " + name));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> paramsSchema(Map<String, Object> tool) {
    Map<String, Object> inputSchema = (Map<String, Object>) tool.get("inputSchema");
    Map<String, Object> properties = (Map<String, Object>) inputSchema.get("properties");
    return (Map<String, Object>) properties.get("params");
  }

  @SuppressWarnings("unchecked")
  private static String firstResourceUri(Map<String, Object> response) {
    Map<String, Object> result = (Map<String, Object>) response.get("result");
    List<Map<String, Object>> resources = (List<Map<String, Object>>) result.get("resources");
    return (String) resources.getFirst().get("uri");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> postInitializedJsonRpc(
      HttpClient client, String endpoint, String method, Map<String, Object> params)
      throws Exception {
    HttpResponse<String> response = sendInitializedRaw(client, endpoint, method, params);
    assertEquals(200, response.statusCode(), response.body());
    return (Map<String, Object>) JsonUtil.parse(response.body());
  }

  private static HttpResponse<String> sendInitializedRaw(
      HttpClient client, String endpoint, String method, Map<String, Object> params)
      throws Exception {
    String body =
        JsonUtil.toJson(
            Map.of("jsonrpc", "2.0", "id", 1, "method", method, "params", params));
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2025-11-25")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
    return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
  }

  private static RunningServer startServer(String sessionId, String toolPrefix) throws Exception {
    IOException lastError = null;
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = freePort();
      AgentDispatcher dispatcher = testDispatcher(sessionId);
      try {
        McpHttpServer server =
            new McpHttpServer(
                new McpConfig("127.0.0.1", port, "/mcp", null, sessionId, toolPrefix), dispatcher);
        server.start();
        return new RunningServer(server, dispatcher, port);
      } catch (BindException bindError) {
        dispatcher.close();
        lastError = bindError;
      }
    }
    throw lastError;
  }

  private static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      return socket.getLocalPort();
    }
  }

  private record RunningServer(McpHttpServer server, AgentDispatcher dispatcher, int port)
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

  private static AgentDispatcher testDispatcher(String sessionId) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));
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
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactions,
            "demo.bin");
    return new AgentDispatcher(services, sessionId);
  }

  private interface MethodHandler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) {
            return null;
          }
          throw new AssertionError("Unexpected call: " + method);
        });
  }

  private static <T> T proxy(Class<T> type, MethodHandler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
