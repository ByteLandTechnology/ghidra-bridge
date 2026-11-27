package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
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
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class McpHttpServerToolResultTest {

  @Test
  void toolResultMatchesLegacyEnvelopeByteForByteAcrossResultTypes() {
    List<Object> payloads =
        List.of(
            sampleDecompilationPayload(),
            sampleMemoryPayload(),
            sampleFunctionListPayload(),
            McpHttpServer.errorPayload(
                new TransactionExecutionException("conflict \"quoted\" \\ \n\t", "symbol.name")),
            "Plain text with \"quotes\", \\slashes\\, and \nnewlines",
            List.of("alpha", 2, true, Map.of("nested", "value")),
            42,
            Boolean.TRUE,
            Double.NaN);

    for (Object payload : payloads) {
      for (boolean isError : new boolean[] {false, true}) {
        for (boolean stateless : new boolean[] {false, true}) {
          String expected =
              JsonUtil.toJson(JsonRpc.success("req-1", legacyToolResult(payload, isError, stateless)));
          String actual =
              JsonUtil.toJson(
                  JsonRpc.success("req-1", McpHttpServer.toolResult(payload, isError, stateless)));
          assertEquals(expected, actual);
        }
      }
    }

    for (boolean stateless : new boolean[] {false, true}) {
      String expectedNull =
          JsonUtil.toJson(JsonRpc.success("req-null", legacyToolResult(null, false, stateless)));
      String actualNull =
          JsonUtil.toJson(
              JsonRpc.success("req-null", McpHttpServer.toolResult(null, false, stateless)));
      assertEquals(expectedNull, actualNull);
    }
  }

  @Test
  void toolResultKeepsUnquotedStringAndWrapsNullAndScalarsInStructuredContentValue() {
    String rawText = "hello \"world\"\nline 2";
    String stringWire =
        JsonUtil.toJson(JsonRpc.success(1, McpHttpServer.toolResult(rawText, false, true)));
    Map<String, Object> parsedStringResult = resultOf(stringWire);
    assertEquals(rawText, firstContentText(parsedStringResult));
    assertEquals(Map.of("value", rawText), parsedStringResult.get("structuredContent"));

    String nullWire =
        JsonUtil.toJson(JsonRpc.success(2, McpHttpServer.toolResult(null, false, false)));
    Map<String, Object> parsedNullResult = resultOf(nullWire);
    assertEquals("null", firstContentText(parsedNullResult));
    Map<String, Object> expectedNullWrapper = new LinkedHashMap<>();
    expectedNullWrapper.put("value", null);
    assertEquals(expectedNullWrapper, parsedNullResult.get("structuredContent"));

    List<Object> listValue = List.of(1, "two", Map.of("three", 3));
    String listWire =
        JsonUtil.toJson(JsonRpc.success(3, McpHttpServer.toolResult(listValue, false, false)));
    Map<String, Object> parsedListResult = resultOf(listWire);
    assertEquals("[1,\"two\",{\"three\":3}]", firstContentText(parsedListResult));
    assertEquals(Map.of("value", listValue), parsedListResult.get("structuredContent"));
  }

  @Test
  void toolResultSerializesNonStringPayloadOnceAndEnforcesNestingLimit() {
    AtomicInteger traversals = new AtomicInteger();
    Map<String, Object> inner = sampleMemoryPayload();
    Map<String, Object> counting =
        new AbstractMap<>() {
          @Override
          public Set<Entry<String, Object>> entrySet() {
            traversals.incrementAndGet();
            return inner.entrySet();
          }
        };

    Map<String, Object> response = McpHttpServer.toolResult(counting, false, true);
    assertEquals(1, traversals.get());

    String outerJson = JsonUtil.toJson(JsonRpc.success("call-1", response));
    assertEquals(1, traversals.get());

    Map<String, Object> result = resultOf(outerJson);
    assertEquals(inner, JsonUtil.parse(firstContentText(result)));
    assertEquals(inner, result.get("structuredContent"));

    Map<String, Object> tooDeep = nestedMaps(501);
    assertThrows(
        IllegalArgumentException.class, () -> McpHttpServer.toolResult(tooDeep, false, false));
  }

  @Test
  void httpAndSseToolsCallPreserveDualContentWireFormat() throws Exception {
    try (ServerHarness harness = ServerHarness.start();
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()) {

      // Verify stateless Streamable HTTP (2026-07-28) across decompilation.get, memory.read,
      // function.list, ghidra_help, and error calls.
      Map<String, Object> decompHttp =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "http-decomp",
              "ghidra_decompilation",
              Map.of("operation", "get", "params", Map.of("selector", Map.of("entry", "0x100000"))));
      assertDualContentParity(decompHttp, false, true);
      assertEquals(
          "get", ((Map<?, ?>) resultMap(decompHttp).get("structuredContent")).get("operation"));

      Map<String, Object> memoryHttp =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "http-mem",
              "ghidra_memory",
              Map.of(
                  "operation",
                  "read",
                  "params",
                  Map.of("selector", Map.of("address", "ram:00100000"), "length", 16)));
      assertDualContentParity(memoryHttp, false, true);

      Map<String, Object> functionsHttp =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "http-fn",
              "ghidra_function",
              Map.of("operation", "list", "params", Map.of("page", Map.of("limit", 2))));
      assertDualContentParity(functionsHttp, false, true);

      Map<String, Object> helpHttp =
          postStatelessToolCall(client, harness.endpoint(), "http-help", "ghidra_help", Map.of());
      assertDualContentParity(helpHttp, false, true);

      Map<String, Object> errorHttp =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "http-err",
              "ghidra_memory",
              Map.of(
                  "operation",
                  "read",
                  "params",
                  Map.of("selector", Map.of("address", "ram:deadbeef"), "length", 4)));
      assertDualContentParity(errorHttp, true, true);
      Map<?, ?> errorStructured = (Map<?, ?>) resultMap(errorHttp).get("structuredContent");
      assertEquals(500, errorStructured.get("status"));
      assertEquals("transaction_failed", errorStructured.get("code"));

      // Verify SSE transport (GET /mcp -> endpoint event -> POST /mcp?sessionId=... -> message event)
      // produces identical content[0].text and structuredContent for success and error calls.
      HttpRequest sseRequest =
          HttpRequest.newBuilder(URI.create(harness.endpoint()))
              .timeout(Duration.ofSeconds(10))
              .header("Accept", "text/event-stream")
              .GET()
              .build();
      HttpResponse<InputStream> sseStream =
          client.send(sseRequest, HttpResponse.BodyHandlers.ofInputStream());
      try (InputStream sseBody = sseStream.body()) {
        assertEquals(200, sseStream.statusCode());

        BlockingQueue<SseEvent> events = new LinkedBlockingQueue<>();
        Thread readerThread =
            new Thread(() -> readSseEvents(sseBody, events), "mcp-sse-test-reader");
        readerThread.setDaemon(true);
        readerThread.start();

        SseEvent endpointEvent = events.poll(10, TimeUnit.SECONDS);
        assertNotNull(endpointEvent, "Timed out waiting for SSE endpoint event");
        assertEquals("endpoint", endpointEvent.event());
        URI sessionUri = URI.create(harness.endpoint()).resolve(endpointEvent.data());

        postSseToolCall(
            client,
            sessionUri,
            "sse-decomp",
            "ghidra_decompilation",
            Map.of("operation", "get", "params", Map.of("selector", Map.of("entry", "0x100000"))));
        SseEvent sseDecompMsg = events.poll(10, TimeUnit.SECONDS);
        assertNotNull(sseDecompMsg, "Timed out waiting for SSE decompilation message event");
        assertEquals("message", sseDecompMsg.event());
        Map<String, Object> decompSse = JsonUtil.parseObject(sseDecompMsg.data());
        assertDualContentParity(decompSse, false, false);
        assertEquals(
            resultMap(decompHttp).get("structuredContent"),
            resultMap(decompSse).get("structuredContent"));
        assertEquals(
            firstContentText(resultMap(decompHttp)), firstContentText(resultMap(decompSse)));

        postSseToolCall(
            client,
            sessionUri,
            "sse-err",
            "ghidra_memory",
            Map.of(
                "operation",
                "read",
                "params",
                Map.of("selector", Map.of("address", "ram:deadbeef"), "length", 4)));
        SseEvent sseErrMsg = events.poll(10, TimeUnit.SECONDS);
        assertNotNull(sseErrMsg, "Timed out waiting for SSE error message event");
        assertEquals("message", sseErrMsg.event());
        Map<String, Object> errorSse = JsonUtil.parseObject(sseErrMsg.data());
        assertDualContentParity(errorSse, true, false);
        assertEquals(
            resultMap(errorHttp).get("structuredContent"),
            resultMap(errorSse).get("structuredContent"));
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void toolsCallValidatesEnvelopesWithWireSchemaAndEmitsPlainEnglishDiagnostics() throws Exception {
    try (ServerHarness harness = ServerHarness.start();
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()) {

      // 1. tools/list publishes compact default metadata and ghidra_help publishes discriminators.
      Map<String, Object> listResp =
          postRawStateless(
              client,
              harness.endpoint(),
              Map.of(
                  "MCP-Protocol-Version", "2026-07-28",
                  "Mcp-Method", "tools/list"),
              Map.of(
                  "jsonrpc", "2.0",
                  "id", "list-1",
                  "method", "tools/list",
                  "params",
                      Map.of(
                          "_meta",
                          Map.of(
                              "io.modelcontextprotocol/protocolVersion", "2026-07-28",
                              "io.modelcontextprotocol/clientCapabilities", Map.of()))),
              200);
      List<Map<String, Object>> tools =
          (List<Map<String, Object>>) resultMap(listResp).get("tools");
      Map<String, Object> memoryTool =
          tools.stream()
              .filter(tool -> "ghidra_memory".equals(tool.get("name")))
              .findFirst()
              .orElseThrow();
      Map<String, Object> memorySchema = (Map<String, Object>) memoryTool.get("inputSchema");
      assertFalse(memorySchema.containsKey("oneOf"));
      Map<String, Object> memoryProps = (Map<String, Object>) memorySchema.get("properties");
      Map<String, Object> memoryParams = (Map<String, Object>) memoryProps.get("params");
      assertEquals(Map.of(), memoryParams.get("default"));
      Map<String, Object> memoryParamProps =
          (Map<String, Object>) memoryParams.get("properties");
      assertEquals(256, ((Map<String, Object>) memoryParamProps.get("length")).get("default"));
      assertEquals("hex", ((Map<String, Object>) memoryParamProps.get("encoding")).get("default"));

      Map<String, Object> helpDomainResp =
          postStatelessToolCall(
              client, harness.endpoint(), "help-dt", "ghidra_help", Map.of("domain", "data_type"));
      Map<String, Object> helpStructured =
          (Map<String, Object>) resultMap(helpDomainResp).get("structuredContent");
      List<Map<String, Object>> dtOperations =
          (List<Map<String, Object>>) helpStructured.get("operations");
      Map<String, Object> dtCreate =
          dtOperations.stream()
              .filter(item -> "create".equals(item.get("name")))
              .findFirst()
              .orElseThrow();
      Map<String, Object> dtCreateSchema = (Map<String, Object>) dtCreate.get("inputSchema");
      Map<String, Object> dtCreateProps =
          (Map<String, Object>) dtCreateSchema.get("properties");
      Map<String, Object> dtResourceSchema =
          (Map<String, Object>) dtCreateProps.get("resource");
      assertEquals(Map.of("propertyName", "kind"), dtResourceSchema.get("discriminator"));

      // 2. Non-object arguments return HTTP 200 isError=true status=400 target=/arguments (never 500).
      Map<String, Object> nonObjectArgs =
          postRawStateless(
              client,
              harness.endpoint(),
              Map.of(
                  "MCP-Protocol-Version", "2026-07-28",
                  "Mcp-Method", "tools/call",
                  "Mcp-Name", "ghidra_memory"),
              Map.of(
                  "jsonrpc", "2.0",
                  "id", "bad-args",
                  "method", "tools/call",
                  "params",
                      Map.of(
                          "_meta",
                              Map.of(
                                  "io.modelcontextprotocol/protocolVersion", "2026-07-28",
                                  "io.modelcontextprotocol/clientCapabilities", Map.of()),
                          "name", "ghidra_memory",
                          "arguments", List.of("bad"))),
              200);
      assertToolBadRequest(nonObjectArgs, "invalid_type", "/arguments", "JSON object");

      // 3. Absent operation, non-text operation, unknown operation, dotted operation, unknown key, bad params.
      Map<String, Object> missingOp =
          postStatelessToolCall(client, harness.endpoint(), "missing-op", "ghidra_memory", Map.of());
      assertToolBadRequest(missingOp, "missing_field", "/operation", "Valid operations:");

      Map<String, Object> numericOp =
          postStatelessToolCall(
              client, harness.endpoint(), "num-op", "ghidra_memory", Map.of("operation", 42));
      assertToolBadRequest(numericOp, "invalid_type", "/operation", "Valid operations:");

      Map<String, Object> dottedSameDomain =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "dotted-op",
              "ghidra_program",
              Map.of("operation", "program.get"));
      assertToolBadRequest(dottedSameDomain, "invalid_enum", "/operation", "Use bare operation \"get\"");

      Map<String, Object> dottedCrossDomain =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "cross-op",
              "ghidra_program",
              Map.of("operation", "memory.read"));
      assertToolBadRequest(dottedCrossDomain, "invalid_enum", "/operation", "ghidra_memory");

      Map<String, Object> unknownDomainArg =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "extra-arg",
              "ghidra_memory",
              Map.of("operation", "read", "unexpected", true));
      assertToolBadRequest(unknownDomainArg, "unknown_field", "/unexpected", "operation, params");

      Map<String, Object> nonObjectParams =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "bad-params",
              "ghidra_memory",
              Map.of("operation", "read", "params", "not-an-object"));
      assertToolBadRequest(nonObjectParams, "invalid_type", "/params", "JSON object");

      // 4. Nested parameter validation preserves parameter-relative target pointers (/selector/address).
      Map<String, Object> badSelector =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "bad-sel",
              "ghidra_memory",
              Map.of("operation", "read", "params", Map.of("selector", Map.of("address", 99))));
      assertToolBadRequest(badSelector, "invalid_type", "/selector/address", "/selector/address");

      // 5. ghidra_help unknown key, operation without domain, and dotted domain/operation suggestions.
      Map<String, Object> badHelpKey =
          postStatelessToolCall(
              client, harness.endpoint(), "help-key", "ghidra_help", Map.of("topic", "memory"));
      assertToolBadRequest(badHelpKey, "unknown_field", "/topic", "domain, operation");

      Map<String, Object> helpOpWithoutDomain =
          postStatelessToolCall(
              client, harness.endpoint(), "help-no-dom", "ghidra_help", Map.of("operation", "get"));
      assertToolBadRequest(helpOpWithoutDomain, "missing_field", "/domain", "Valid domains:");

      Map<String, Object> helpDottedDomain =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "help-dot-dom",
              "ghidra_help",
              Map.of("domain", "program.get"));
      assertToolBadRequest(helpDottedDomain, "invalid_enum", "/domain", "Use bare domain \"program\"");

      Map<String, Object> helpDottedOp =
          postStatelessToolCall(
              client,
              harness.endpoint(),
              "help-dot-op",
              "ghidra_help",
              Map.of("domain", "program", "operation", "program.get"));
      assertToolBadRequest(helpDottedOp, "invalid_enum", "/operation", "Use bare operation \"get\"");

      // 6. Unknown tool name rethrows JsonRpcError (-32602) with bare-name suggestion and valid tools.
      Map<String, Object> unknownToolRpc =
          postRawStateless(
              client,
              harness.endpoint(),
              Map.of(
                  "MCP-Protocol-Version", "2026-07-28",
                  "Mcp-Method", "tools/call",
                  "Mcp-Name", "program.get"),
              Map.of(
                  "jsonrpc", "2.0",
                  "id", "bad-tool",
                  "method", "tools/call",
                  "params",
                      Map.of(
                          "_meta",
                              Map.of(
                                  "io.modelcontextprotocol/protocolVersion", "2026-07-28",
                                  "io.modelcontextprotocol/clientCapabilities", Map.of()),
                          "name", "program.get",
                          "arguments", Map.of())),
              400);
      Map<String, Object> rpcError = (Map<String, Object>) unknownToolRpc.get("error");
      assertEquals(-32602, ((Number) rpcError.get("code")).intValue());
      String unknownToolMsg = String.valueOf(rpcError.get("message"));
      assertTrue(unknownToolMsg.contains("ghidra_program"));
      assertTrue(unknownToolMsg.contains("Valid tools:"));

      // 7. Header and protocol-version errors use plain English without HeaderMismatch or UnsupportedProtocolVersionError.
      Map<String, Object> headerErr =
          postRawStateless(
              client,
              harness.endpoint(),
              Map.of(
                  "MCP-Protocol-Version", "2026-07-28",
                  "Mcp-Method", "tools/list"),
              Map.of(
                  "jsonrpc", "2.0",
                  "id", "hdr-err",
                  "method", "tools/call",
                  "params",
                      Map.of(
                          "_meta",
                              Map.of(
                                  "io.modelcontextprotocol/protocolVersion", "2026-07-28",
                                  "io.modelcontextprotocol/clientCapabilities", Map.of()),
                          "name", "ghidra_help")),
              400);
      String headerMsg =
          String.valueOf(((Map<String, Object>) headerErr.get("error")).get("message"));
      assertFalse(headerMsg.contains("HeaderMismatch"));
      assertTrue(headerMsg.contains("Mcp-Method"));

      Map<String, Object> versionErr =
          postRawStateless(
              client,
              harness.endpoint(),
              Map.of(
                  "MCP-Protocol-Version", "2099-01-01",
                  "Mcp-Method", "tools/list"),
              Map.of(
                  "jsonrpc", "2.0",
                  "id", "ver-err",
                  "method", "tools/list",
                  "params",
                      Map.of(
                          "_meta",
                              Map.of(
                                  "io.modelcontextprotocol/protocolVersion", "2099-01-01",
                                  "io.modelcontextprotocol/clientCapabilities", Map.of()))),
              400);
      String versionMsg =
          String.valueOf(((Map<String, Object>) versionErr.get("error")).get("message"));
      assertFalse(versionMsg.contains("UnsupportedProtocolVersionError"));
      assertTrue(versionMsg.contains("2026-07-28"));

      Map<String, Object> initVersionErr =
          postRawStateless(
              client,
              harness.endpoint(),
              Map.of("MCP-Protocol-Version", "1999-01-01"),
              Map.of(
                  "jsonrpc", "2.0",
                  "id", "init-ver-err",
                  "method", "initialize",
                  "params", Map.of("protocolVersion", "2025-03-26", "capabilities", Map.of())),
              400);
      String initVersionMsg =
          String.valueOf(((Map<String, Object>) initVersionErr.get("error")).get("message"));
      assertTrue(initVersionMsg.contains("Supported protocol versions:"));
    }
  }

  private static void assertToolBadRequest(
      Map<String, Object> rpcEnvelope,
      String expectedCode,
      String expectedTarget,
      String expectedMessageSubstring) {
    assertDualContentParity(rpcEnvelope, true, true);
    Map<?, ?> structured = (Map<?, ?>) resultMap(rpcEnvelope).get("structuredContent");
    assertEquals(400, structured.get("status"));
    assertEquals(expectedCode, structured.get("code"));
    assertEquals(expectedTarget, structured.get("target"));
    String message = String.valueOf(structured.get("message"));
    assertTrue(
        message.contains(expectedMessageSubstring),
        "Expected message to contain <" + expectedMessageSubstring + "> but got: " + message);
  }

  private static Map<String, Object> postRawStateless(
      HttpClient client,
      String endpoint,
      Map<String, String> extraHeaders,
      Map<String, Object> requestBody,
      int expectedHttpStatus)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(URI.create(endpoint))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(requestBody)));
    extraHeaders.forEach(builder::header);
    HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    assertEquals(expectedHttpStatus, response.statusCode());
    return JsonUtil.parseObject(response.body());
  }

  private static void assertDualContentParity(
      Map<String, Object> rpcEnvelope, boolean expectedError, boolean expectedStateless) {
    assertEquals("2.0", rpcEnvelope.get("jsonrpc"));
    Map<String, Object> result = resultMap(rpcEnvelope);
    assertEquals(expectedError, result.get("isError"));
    if (expectedStateless) {
      assertEquals("complete", result.get("resultType"));
    } else {
      assertFalse(result.containsKey("resultType"));
    }
    String text = firstContentText(result);
    Object parsedText = JsonUtil.parse(text);
    assertEquals(result.get("structuredContent"), parsedText);
    assertTrue(result.get("structuredContent") instanceof Map<?, ?>);
  }

  private static Map<String, Object> postStatelessToolCall(
      HttpClient client,
      String endpoint,
      String id,
      String toolName,
      Map<String, Object> arguments)
      throws IOException, InterruptedException {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put(
        "_meta",
        Map.of(
            "io.modelcontextprotocol/protocolVersion",
            "2026-07-28",
            "io.modelcontextprotocol/clientInfo",
            Map.of("name", "mcp-test", "version", "1.0.0"),
            "io.modelcontextprotocol/clientCapabilities",
            Map.of()));
    params.put("name", toolName);
    params.put("arguments", arguments);

    Map<String, Object> requestBody = new LinkedHashMap<>();
    requestBody.put("jsonrpc", "2.0");
    requestBody.put("id", id);
    requestBody.put("method", "tools/call");
    requestBody.put("params", params);

    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", toolName)
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(requestBody)))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    return JsonUtil.parseObject(response.body());
  }

  private static void postSseToolCall(
      HttpClient client, URI sessionUri, String id, String toolName, Map<String, Object> arguments)
      throws IOException, InterruptedException {
    Map<String, Object> requestBody = new LinkedHashMap<>();
    requestBody.put("jsonrpc", "2.0");
    requestBody.put("id", id);
    requestBody.put("method", "tools/call");
    requestBody.put("params", Map.of("name", toolName, "arguments", arguments));

    HttpRequest request =
        HttpRequest.newBuilder(sessionUri)
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(requestBody)))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(202, response.statusCode());
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

  private static Map<String, Object> legacyToolResult(
      Object result, boolean isError, boolean statelessProtocol) {
    Map<String, Object> content = new LinkedHashMap<>();
    content.put("type", "text");
    content.put("text", result instanceof String string ? string : JsonUtil.toJson(result));

    Map<String, Object> response = new LinkedHashMap<>();
    if (statelessProtocol) {
      response.put("resultType", "complete");
    }
    response.put("content", List.of(content));
    if (result instanceof Map<?, ?>) {
      response.put("structuredContent", result);
    } else {
      Map<String, Object> wrapper = new LinkedHashMap<>();
      wrapper.put("value", result);
      response.put("structuredContent", wrapper);
    }
    response.put("isError", isError);
    return response;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> resultOf(String wireJson) {
    return resultMap(JsonUtil.parseObject(wireJson));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> resultMap(Map<String, Object> rpcEnvelope) {
    return (Map<String, Object>) rpcEnvelope.get("result");
  }

  private static String firstContentText(Map<String, Object> result) {
    List<?> content = (List<?>) result.get("content");
    assertEquals(1, content.size());
    Map<?, ?> first = (Map<?, ?>) content.getFirst();
    assertEquals("text", first.get("type"));
    return (String) first.get("text");
  }

  private static Map<String, Object> sampleDecompilationPayload() {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("entry", "ram:00100000");
    result.put("name", "main");
    result.put("format", "text");
    result.put("completed", true);
    result.put("elapsed_ms", 18);
    result.put("c", "int main(int argc, char **argv) {\n  puts(\"hello \\\"bridge\\\"\");\n  return 0;\n}\n");
    result.put("warnings", List.of());
    return Map.of("operation", "get", "result", result);
  }

  private static Map<String, Object> sampleMemoryPayload() {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("address", "ram:00100000");
    result.put("bytes", Map.of("encoding", "hex", "data", "7f454c46020101000000000000000000", "length", 16));
    return Map.of("operation", "read", "result", result);
  }

  private static Map<String, Object> sampleFunctionListPayload() {
    List<Map<String, Object>> items = new ArrayList<>();
    for (int i = 0; i < 4; i++) {
      Map<String, Object> fn = new LinkedHashMap<>();
      fn.put("entry", String.format("ram:00100%d00", i));
      fn.put("name", "func_" + i);
      fn.put("parameter_count", i);
      fn.put("signature", "int func_" + i + "(void)");
      items.add(fn);
    }
    return Map.of(
        "operation",
        "list",
        "result",
        Map.of(
            "items",
            items,
            "scan",
            Map.of("kind", "address", "complete", true, "stop_reason", "completed", "elapsed_ms", 2)));
  }

  private static Map<String, Object> nestedMaps(int depth) {
    Map<String, Object> current = Map.of();
    for (int i = 1; i < depth; i++) {
      current = Map.of("n", current);
    }
    return current;
  }

  private static final class ServerHarness implements AutoCloseable {
    private final AgentDispatcher dispatcher;
    private final McpHttpServer server;

    private ServerHarness(AgentDispatcher dispatcher, McpHttpServer server) {
      this.dispatcher = dispatcher;
      this.server = server;
    }

    static ServerHarness start() throws IOException {
      BridgeServices services = createStubServices();
      AgentDispatcher dispatcher = new AgentDispatcher(services, "test");
      for (int attempt = 0; attempt < 10; attempt++) {
        int port = reserveLoopbackPort();
        McpConfig config = new McpConfig("127.0.0.1", port, "/mcp", null, "test", "ghidra");
        try {
          McpHttpServer server = new McpHttpServer(config, dispatcher);
          server.start();
          return new ServerHarness(dispatcher, server);
        } catch (BindException retry) {
          if (attempt == 9) {
            dispatcher.close();
            throw retry;
          }
        }
      }
      throw new IllegalStateException("Unable to bind test server");
    }

    String endpoint() {
      return server.endpoint();
    }

    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }

    private static int reserveLoopbackPort() throws IOException {
      try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
        return socket.getLocalPort();
      }
    }

    private static BridgeServices createStubServices() {
      DecompilationService decompilation =
          proxy(
              DecompilationService.class,
              (method, args) -> {
                if ("close".equals(method)) return null;
                assertEquals("decompileFunction", method);
                return new DecompilationResource(
                    "ram:00100000",
                    "main",
                    DecompilationResource.Format.TEXT,
                    true,
                    12L,
                    "int main(void) {\n  puts(\"hello \\\"mcp\\\"\");\n  return 0;\n}\n",
                    null,
                    null,
                    null,
                    null,
                    null,
                    List.of());
              });
      MemoryService memory =
          proxy(
              MemoryService.class,
              (method, args) -> {
                assertEquals("readMemoryRange", method);
                String address = (String) args[0];
                int length = (Integer) args[1];
                if ("ram:deadbeef".equals(address)) {
                  throw new TransactionExecutionException("unmapped memory at " + address);
                }
                return new MemoryResource(
                    address,
                    new ByteSequence(ByteSequence.Encoding.HEX, "7f454c46".repeat(length / 4), length));
              });
      FunctionService functions =
          proxy(
              FunctionService.class,
              (method, args) -> {
                assertEquals("listFunctions", method);
                List<FunctionResource> list =
                    List.of(
                        new FunctionResource(
                            "ram:00100000",
                            "func_0",
                            "Global",
                            new FunctionResource.Body("ram:00100000", "ram:0010001f", 32L),
                            "int func_0(int arg0)",
                            new DataTypeReference.Named("int"),
                            new VariableStorageReference.Register("EAX"),
                            1,
                            "__stdcall",
                            null,
                            null,
                            "Entry function",
                            false,
                            false,
                            false,
                            false,
                            null,
                            false,
                            false,
                            null,
                            List.of("entry"),
                            null),
                        new FunctionResource(
                            "ram:00100020",
                            "func_1",
                            "Global",
                            new FunctionResource.Body("ram:00100020", "ram:0010003f", 32L),
                            "void func_1(void)",
                            new DataTypeReference.Named("void"),
                            null,
                            0,
                            "__stdcall",
                            null,
                            null,
                            null,
                            false,
                            false,
                            false,
                            false,
                            null,
                            false,
                            false,
                            null,
                            List.of(),
                            null));
                return Page.scanned(
                    list,
                    2,
                    null,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        "ram:00100000",
                        "ram:0010003f",
                        "ram:00100000",
                        "ram:0010003f",
                        true,
                        ScanProgress.StopReason.COMPLETED,
                        3L));
              });
      AnalysisService analysis =
          proxy(
              AnalysisService.class,
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
          unused(ProgramService.class),
          unused(AddressService.class),
          unused(CommentService.class),
          unused(ReferenceService.class),
          memory,
          unused(ListingService.class),
          functions,
          unused(GlobalVariableService.class),
          analysis,
          decompilation,
          unused(SymbolService.class),
          unused(DataTypeService.class),
          tx,
          "fixture");
    }

    private interface MethodHandler {
      Object invoke(String method, Object[] args);
    }

    private static <T> T unused(Class<T> type) {
      return proxy(
          type,
          (method, args) -> {
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
}
