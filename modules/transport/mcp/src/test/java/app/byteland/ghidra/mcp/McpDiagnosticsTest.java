package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
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
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class McpDiagnosticsTest {
  private static final List<String> DOMAIN_TOOLS =
      List.of(
          "ghidra_bridge",
          "ghidra_analysis",
          "ghidra_program",
          "ghidra_address",
          "ghidra_memory",
          "ghidra_listing",
          "ghidra_decompilation",
          "ghidra_function",
          "ghidra_global_variable",
          "ghidra_comment",
          "ghidra_reference",
          "ghidra_symbol",
          "ghidra_data_type",
          "ghidra_batch");

  private AgentDispatcher dispatcher;
  private McpHttpServer server;
  private HttpClient client;
  private URI endpoint;

  @BeforeEach
  void setUp() throws IOException {
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) ->
                new ProgramResource(
                    "sample.bin",
                    "/sample.bin",
                    "ELF",
                    "0x00100000",
                    "0x00100000",
                    "0x00101000",
                    "x86:LE:64:default",
                    "gcc",
                    Instant.parse("2026-01-01T00:00:00Z"),
                    Instant.parse("2026-01-01T00:00:00Z"),
                    1,
                    1));
    AnalysisService analysisService =
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
            } catch (RuntimeException error) {
              throw error;
            } catch (Exception error) {
              throw new RuntimeException(error);
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
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactions,
            "sample.bin");
    int port = findFreePort();
    dispatcher =
        new AgentDispatcher(
            services, new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "sess-1", null));
    server =
        new McpHttpServer(
            new McpConfig("127.0.0.1", port, "/mcp", null, "sess-1", "ghidra"), dispatcher);
    server.start();
    client = HttpClient.newHttpClient();
    endpoint = URI.create(server.endpoint());
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
  void invalidDomainToolInputsReturn400AcrossAll14DomainTools() throws Exception {
    for (String toolName : DOMAIN_TOOLS) {
      Map<String, Object> emptyArgsError = callToolExpectingError(toolName, Map.of());
      assertEquals(400, emptyArgsError.get("status"), toolName);
      assertEquals("missing_field", emptyArgsError.get("code"), toolName);
      assertEquals("/operation", emptyArgsError.get("target"), toolName);
      String emptyMessage = String.valueOf(emptyArgsError.get("message"));
      assertTrue(emptyMessage.contains("Valid operations are:"), emptyMessage);
      assertNoForbiddenLabels(emptyMessage);

      Map<String, Object> dottedError =
          callToolExpectingError(toolName, Map.of("operation", "program.get"));
      assertEquals(400, dottedError.get("status"), toolName);
      assertEquals("invalid_enum", dottedError.get("code"), toolName);
      assertEquals("/operation", dottedError.get("target"), toolName);
      String dottedMessage = String.valueOf(dottedError.get("message"));
      assertTrue(dottedMessage.contains("\"get\""), dottedMessage);
      assertTrue(dottedMessage.contains("Valid operations"), dottedMessage);
      assertNoForbiddenLabels(dottedMessage);

      String validOperation = firstValidOperation(toolName);
      Map<String, Object> nonObjectParamsError =
          callToolExpectingError(
              toolName, Map.of("operation", validOperation, "params", "not-an-object"));
      assertEquals(400, nonObjectParamsError.get("status"), toolName);
      assertEquals("invalid_type", nonObjectParamsError.get("code"), toolName);
      assertEquals("/params", nonObjectParamsError.get("target"), toolName);
      assertNoForbiddenLabels(String.valueOf(nonObjectParamsError.get("message")));

      Map<String, Object> extraKeyError =
          callToolExpectingError(
              toolName, Map.of("operation", validOperation, "unexpected_key", true));
      assertEquals(400, extraKeyError.get("status"), toolName);
      assertEquals("unknown_field", extraKeyError.get("code"), toolName);
      assertEquals("/unexpected_key", extraKeyError.get("target"), toolName);
      String extraKeyMessage = String.valueOf(extraKeyError.get("message"));
      assertTrue(extraKeyMessage.contains("unexpected_key"), extraKeyMessage);
      assertTrue(extraKeyMessage.contains("operation, params"), extraKeyMessage);
      assertNoForbiddenLabels(extraKeyMessage);
    }
  }

  @Test
  void dottedOperationsSuggestExactBareOperationNames() throws Exception {
    assertDottedSuggestion("ghidra_program", "program.get", "\"get\"");
    assertDottedSuggestion("ghidra_bridge", "session.get", "\"get\"");
    assertDottedSuggestion("ghidra_memory", "memory_block.list", "\"block.list\"");
    assertDottedSuggestion("ghidra_listing", "listing.code_unit.list", "\"code_unit.list\"");
    assertDottedSuggestion("ghidra_function", "function_call.list", "\"call.list\"");
    assertDottedSuggestion("ghidra_data_type", "data_type_category.list", "\"category.list\"");
  }

  @Test
  void helpToolValidatesArgumentsAndSuggestsBareNamesWith400Status() throws Exception {
    Map<String, Object> okResult = callToolExpectingSuccess("ghidra_help", Map.of());
    @SuppressWarnings("unchecked")
    List<String> returnedDomains = (List<String>) okResult.get("domains");
    assertEquals(14, returnedDomains.size());
    assertEquals(java.util.Set.copyOf(DOMAIN_TOOLS), java.util.Set.copyOf(returnedDomains));

    Map<String, Object> extraError =
        callToolExpectingError("ghidra_help", Map.of("unknown_arg", "x"));
    assertEquals(400, extraError.get("status"));
    assertEquals("unknown_field", extraError.get("code"));
    assertEquals("/unknown_arg", extraError.get("target"));
    assertTrue(String.valueOf(extraError.get("message")).contains("unknown_arg"));
    assertTrue(String.valueOf(extraError.get("message")).contains("domain, operation"));

    Map<String, Object> missingDomainWithDottedOp =
        callToolExpectingError("ghidra_help", Map.of("operation", "program.get"));
    assertEquals(400, missingDomainWithDottedOp.get("status"));
    assertEquals("missing_field", missingDomainWithDottedOp.get("code"));
    assertEquals("/domain", missingDomainWithDottedOp.get("target"));
    assertTrue(String.valueOf(missingDomainWithDottedOp.get("message")).contains("ghidra_program"));
    assertTrue(String.valueOf(missingDomainWithDottedOp.get("message")).contains("\"get\""));

    Map<String, Object> dottedDomain =
        callToolExpectingError("ghidra_help", Map.of("domain", "program.get"));
    assertEquals(400, dottedDomain.get("status"));
    assertEquals("invalid_enum", dottedDomain.get("code"));
    assertEquals("/domain", dottedDomain.get("target"));
    assertTrue(String.valueOf(dottedDomain.get("message")).contains("ghidra_program"));
    assertTrue(String.valueOf(dottedDomain.get("message")).contains("\"get\""));

    Map<String, Object> dottedOperation =
        callToolExpectingError(
            "ghidra_help", Map.of("domain", "ghidra_program", "operation", "program.get"));
    assertEquals(400, dottedOperation.get("status"));
    assertEquals("invalid_enum", dottedOperation.get("code"));
    assertEquals("/operation", dottedOperation.get("target"));
    assertTrue(String.valueOf(dottedOperation.get("message")).contains("\"get\""));
    assertTrue(String.valueOf(dottedOperation.get("message")).contains("Valid operations"));
  }

  @Test
  void statelessMetadataAndHeaderMismatchesReturnPlainEnglishWithoutInternalClassNames()
      throws Exception {
    Map<String, Object> meta = new LinkedHashMap<>();
    meta.put("io.modelcontextprotocol/protocolVersion", "2026-07-28");
    meta.put("io.modelcontextprotocol/clientCapabilities", Map.of());

    Map<String, Object> requestBody =
        Map.of(
            "jsonrpc",
            "2.0",
            "id",
            1,
            "method",
            "tools/call",
            "params",
            Map.of(
                "name",
                "ghidra_program",
                "arguments",
                Map.of("operation", "get"),
                "_meta",
                meta));

    HttpResponse<String> wrongNameResponse =
        post(
            requestBody,
            Map.of(
                "MCP-Protocol-Version", "2026-07-28",
                "Mcp-Method", "tools/call",
                "Mcp-Name", "wrong_tool"));
    assertEquals(400, wrongNameResponse.statusCode());
    Map<String, Object> wrongNameError = extractRpcError(wrongNameResponse);
    assertEquals(-32020, ((Number) wrongNameError.get("code")).intValue());
    String wrongNameMessage = String.valueOf(wrongNameError.get("message"));
    assertTrue(wrongNameMessage.contains("Mcp-Name"), wrongNameMessage);
    assertTrue(wrongNameMessage.contains("wrong_tool"), wrongNameMessage);
    assertTrue(wrongNameMessage.contains("ghidra_program"), wrongNameMessage);
    assertNoForbiddenLabels(wrongNameMessage);

    HttpResponse<String> missingHeaderResponse =
        post(
            requestBody,
            Map.of(
                "MCP-Protocol-Version", "2026-07-28",
                "Mcp-Method", "tools/call"));
    assertEquals(400, missingHeaderResponse.statusCode());
    Map<String, Object> missingHeaderError = extractRpcError(missingHeaderResponse);
    assertEquals(-32020, ((Number) missingHeaderError.get("code")).intValue());
    String missingHeaderMessage = String.valueOf(missingHeaderError.get("message"));
    assertTrue(missingHeaderMessage.contains("Mcp-Name"), missingHeaderMessage);
    assertTrue(missingHeaderMessage.contains("ghidra_program"), missingHeaderMessage);
    assertNoForbiddenLabels(missingHeaderMessage);

    Map<String, Object> badVersionMeta = new LinkedHashMap<>();
    badVersionMeta.put("io.modelcontextprotocol/protocolVersion", "2025-11-25");
    badVersionMeta.put("io.modelcontextprotocol/clientCapabilities", Map.of());
    Map<String, Object> badVersionBody =
        Map.of(
            "jsonrpc",
            "2.0",
            "id",
            2,
            "method",
            "tools/list",
            "params",
            Map.of("_meta", badVersionMeta));
    HttpResponse<String> badVersionResponse =
        post(
            badVersionBody,
            Map.of(
                "MCP-Protocol-Version", "2025-11-25",
                "Mcp-Method", "tools/list"));
    assertEquals(400, badVersionResponse.statusCode());
    Map<String, Object> badVersionError = extractRpcError(badVersionResponse);
    assertEquals(-32022, ((Number) badVersionError.get("code")).intValue());
    String badVersionMessage = String.valueOf(badVersionError.get("message"));
    assertTrue(
        badVersionMessage.contains("io.modelcontextprotocol/protocolVersion"), badVersionMessage);
    assertTrue(badVersionMessage.contains("2025-11-25"), badVersionMessage);
    assertTrue(badVersionMessage.contains("2026-07-28"), badVersionMessage);
    assertNoForbiddenLabels(badVersionMessage);
    @SuppressWarnings("unchecked")
    Map<String, Object> errorData = (Map<String, Object>) badVersionError.get("data");
    assertNotNull(errorData);
    assertEquals("2025-11-25", errorData.get("requested"));
  }

  @Test
  void unknownToolAndInvalidArgumentsEnvelopePreserveJsonRpc400Codes() throws Exception {
    HttpResponse<String> unknownToolResponse =
        post(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                10,
                "method",
                "tools/call",
                "params",
                Map.of("name", "program.get", "arguments", Map.of())),
            Map.of());
    assertEquals(400, unknownToolResponse.statusCode());
    Map<String, Object> unknownToolError = extractRpcError(unknownToolResponse);
    assertEquals(-32602, ((Number) unknownToolError.get("code")).intValue());
    String message = String.valueOf(unknownToolError.get("message"));
    assertTrue(message.contains("ghidra_program"), message);
    assertTrue(message.contains("\"get\""), message);
    assertTrue(message.contains("Valid tools are:"), message);

    HttpResponse<String> badArgsEnvelope =
        post(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                11,
                "method",
                "tools/call",
                "params",
                Map.of("name", "ghidra_program", "arguments", List.of("bad"))),
            Map.of());
    assertEquals(400, badArgsEnvelope.statusCode());
    Map<String, Object> badArgsError = extractRpcError(badArgsEnvelope);
    assertEquals(-32602, ((Number) badArgsError.get("code")).intValue());
  }

  @Test
  @SuppressWarnings("unchecked")
  void unknownDomainOperationMatchesClientToolErrorContractAcrossStatelessHttpAndSse()
      throws Exception {
    Map<String, Object> meta =
        Map.of(
            "io.modelcontextprotocol/protocolVersion", "2026-07-28",
            "io.modelcontextprotocol/clientInfo", Map.of("name", "mcp-client", "version", "1.0.0"),
            "io.modelcontextprotocol/clientCapabilities", Map.of());

    HttpResponse<String> statelessUnknownOp =
        post(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                "stateless-op",
                "method",
                "tools/call",
                "params",
                Map.of(
                    "_meta", meta,
                    "name", "ghidra_program",
                    "arguments", Map.of("operation", "program.get"))),
            Map.of(
                "MCP-Protocol-Version", "2026-07-28",
                "Mcp-Method", "tools/call",
                "Mcp-Name", "ghidra_program"));
    assertEquals(200, statelessUnknownOp.statusCode());
    Map<String, Object> statelessEnvelope =
        (Map<String, Object>) JsonUtil.parse(statelessUnknownOp.body());
    Map<String, Object> statelessResult = (Map<String, Object>) statelessEnvelope.get("result");
    assertEquals("complete", statelessResult.get("resultType"));
    assertEquals(true, statelessResult.get("isError"));
    Map<String, Object> statelessStructured =
        (Map<String, Object>) statelessResult.get("structuredContent");
    assertEquals(400, statelessStructured.get("status"));
    assertEquals("invalid_enum", statelessStructured.get("code"));
    assertEquals("/operation", statelessStructured.get("target"));
    assertTrue(String.valueOf(statelessStructured.get("message")).contains("\"get\""));
    List<?> statelessContent = (List<?>) statelessResult.get("content");
    assertEquals(1, statelessContent.size());
    assertEquals(
        statelessStructured,
        JsonUtil.parse(String.valueOf(((Map<?, ?>) statelessContent.getFirst()).get("text"))));

    HttpResponse<String> statelessUnknownTool =
        post(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                "stateless-tool",
                "method",
                "tools/call",
                "params",
                Map.of(
                    "_meta", meta,
                    "name", "ghidra_nonexistent",
                    "arguments", Map.of())),
            Map.of(
                "MCP-Protocol-Version", "2026-07-28",
                "Mcp-Method", "tools/call",
                "Mcp-Name", "ghidra_nonexistent"));
    assertEquals(400, statelessUnknownTool.statusCode());
    assertEquals(-32602, ((Number) extractRpcError(statelessUnknownTool).get("code")).intValue());

    HttpRequest sseGet =
        HttpRequest.newBuilder(endpoint).header("Accept", "text/event-stream").GET().build();
    HttpResponse<InputStream> sseStream =
        client.send(sseGet, HttpResponse.BodyHandlers.ofInputStream());
    assertEquals(200, sseStream.statusCode());

    BlockingQueue<SseEvent> sseEvents = new LinkedBlockingQueue<>();
    Thread reader =
        new Thread(() -> readSseEvents(sseStream.body(), sseEvents), "mcp-diag-sse-reader");
    reader.setDaemon(true);
    reader.start();

    try {
      SseEvent endpointEvent = sseEvents.poll(5, TimeUnit.SECONDS);
      assertNotNull(endpointEvent);
      assertEquals("endpoint", endpointEvent.event());
      URI sessionUri = endpoint.resolve(endpointEvent.data());

      HttpResponse<String> sseUnknownOpPost =
          postTo(
              sessionUri,
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  "sse-op",
                  "method",
                  "tools/call",
                  "params",
                  Map.of(
                      "name", "ghidra_program",
                      "arguments", Map.of("operation", "program.get"))));
      assertEquals(202, sseUnknownOpPost.statusCode());
      SseEvent sseOpEvent = sseEvents.poll(5, TimeUnit.SECONDS);
      assertNotNull(sseOpEvent);
      assertEquals("message", sseOpEvent.event());
      Map<String, Object> sseOpEnvelope = JsonUtil.parseObject(sseOpEvent.data());
      Map<String, Object> sseOpResult = (Map<String, Object>) sseOpEnvelope.get("result");
      assertEquals(true, sseOpResult.get("isError"));
      assertEquals(statelessStructured, sseOpResult.get("structuredContent"));

      HttpResponse<String> sseUnknownToolPost =
          postTo(
              sessionUri,
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  "sse-tool",
                  "method",
                  "tools/call",
                  "params",
                  Map.of("name", "ghidra_nonexistent", "arguments", Map.of())));
      assertEquals(202, sseUnknownToolPost.statusCode());
      SseEvent sseToolEvent = sseEvents.poll(5, TimeUnit.SECONDS);
      assertNotNull(sseToolEvent);
      assertEquals("message", sseToolEvent.event());
      Map<String, Object> sseToolEnvelope = JsonUtil.parseObject(sseToolEvent.data());
      Map<String, Object> sseToolError = (Map<String, Object>) sseToolEnvelope.get("error");
      assertEquals(-32602, ((Number) sseToolError.get("code")).intValue());
    } finally {
      sseStream.body().close();
    }
  }

  private void assertDottedSuggestion(String toolName, String dottedOperation, String expectedBare)
      throws Exception {
    Map<String, Object> error =
        callToolExpectingError(toolName, Map.of("operation", dottedOperation));
    assertEquals(400, error.get("status"));
    assertEquals("invalid_enum", error.get("code"));
    assertEquals("/operation", error.get("target"));
    String message = String.valueOf(error.get("message"));
    assertTrue(message.contains(expectedBare), message);
  }

  @SuppressWarnings("unchecked")
  private String firstValidOperation(String toolName) throws Exception {
    Map<String, Object> help =
        callToolExpectingSuccess("ghidra_help", Map.of("domain", toolName));
    List<String> operations = (List<String>) help.get("operations");
    assertFalse(operations.isEmpty());
    return operations.getFirst();
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> callToolExpectingSuccess(
      String toolName, Map<String, Object> arguments) throws Exception {
    Map<String, Object> result = sendToolCall(toolName, arguments);
    assertEquals(false, result.get("isError"));
    return (Map<String, Object>) result.get("structuredContent");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> callToolExpectingError(
      String toolName, Map<String, Object> arguments) throws Exception {
    Map<String, Object> result = sendToolCall(toolName, arguments);
    assertEquals(true, result.get("isError"));
    return (Map<String, Object>) result.get("structuredContent");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> sendToolCall(String toolName, Map<String, Object> arguments)
      throws Exception {
    HttpResponse<String> response =
        post(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                1,
                "method",
                "tools/call",
                "params",
                Map.of("name", toolName, "arguments", arguments)),
            Map.of());
    assertEquals(200, response.statusCode());
    Map<String, Object> envelope = (Map<String, Object>) JsonUtil.parse(response.body());
    return (Map<String, Object>) envelope.get("result");
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> extractRpcError(HttpResponse<String> response) {
    Map<String, Object> envelope = (Map<String, Object>) JsonUtil.parse(response.body());
    Map<String, Object> error = (Map<String, Object>) envelope.get("error");
    assertNotNull(error);
    return error;
  }

  private HttpResponse<String> post(Map<String, Object> body, Map<String, String> headers)
      throws Exception {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(endpoint)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(body)));
    headers.forEach(builder::header);
    return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> postTo(URI targetUri, Map<String, Object> body) throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(targetUri)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(body)))
            .build();
    return client.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private static void readSseEvents(InputStream body, BlockingQueue<SseEvent> sink) {
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8))) {
      String event = null;
      StringBuilder data = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        if (line.isEmpty()) {
          if (event != null || !data.isEmpty()) {
            sink.offer(new SseEvent(event, data.toString()));
            event = null;
            data.setLength(0);
          }
          continue;
        }
        if (line.startsWith(":")) {
          continue;
        }
        if (line.startsWith("event:")) {
          event = line.substring("event:".length()).trim();
        } else if (line.startsWith("data:")) {
          if (!data.isEmpty()) {
            data.append('\n');
          }
          data.append(line.substring("data:".length()).trim());
        }
      }
    } catch (IOException ignored) {
      // Closed at end of test.
    }
  }

  private record SseEvent(String event, String data) {}

  private static void assertNoForbiddenLabels(String message) {
    assertFalse(message.contains("HeaderMismatch"), message);
    assertFalse(message.contains("UnsupportedProtocolVersionError"), message);
    assertFalse(message.contains("Exception"), message);
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private interface Invocation {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("Unexpected service call: " + method);
        });
  }

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              return invocation.invoke(method.getName(), args);
            }));
  }
}
