package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
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
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpHttpServerTest {
  @Test
  @SuppressWarnings("unchecked")
  void coercesStringifiedArgumentsAndParamsAndRejectsNonObjects() throws Exception {
    AddressService addresses =
        proxy(
            AddressService.class,
            (method, args) ->
                new AddressResource(
                    "ram:00001000", true, false, null, null, null, null));
    TransactionRunner transaction =
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
            unused(ProgramService.class),
            addresses,
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
            transaction,
            "test-program");

    try (TestServer handle = startServer(services)) {
      HttpClient client = HttpClient.newHttpClient();

      // Stringified arguments and stringified params coerce cleanly.
      HttpResponse<String> okStringified =
          post(
              client,
              handle.endpoint(),
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
                      "ghidra_address",
                      "arguments",
                      "{\"operation\":\"resolve\",\"params\":\"{\\\"selector\\\":{\\\"address\\\":\\\"0x1000\\\"}}\"}")));
      assertEquals(200, okStringified.statusCode());
      Map<String, Object> okBody = (Map<String, Object>) JsonUtil.parse(okStringified.body());
      Map<String, Object> okResult = (Map<String, Object>) okBody.get("result");
      assertEquals(false, okResult.get("isError"));
      Map<String, Object> structured =
          (Map<String, Object>) okResult.get("structuredContent");
      assertEquals("resolve", structured.get("operation"));

      // Null arguments on ghidra_help succeed.
      Map<String, Object> nullArgsParams = new LinkedHashMap<>();
      nullArgsParams.put("name", "ghidra_help");
      nullArgsParams.put("arguments", null);
      HttpResponse<String> okNullArgs =
          post(
              client,
              handle.endpoint(),
              Map.of("jsonrpc", "2.0", "id", 2, "method", "tools/call", "params", nullArgsParams));
      assertEquals(200, okNullArgs.statusCode());
      Map<String, Object> nullArgsResult =
          (Map<String, Object>)
              ((Map<String, Object>) JsonUtil.parse(okNullArgs.body())).get("result");
      assertFalse((Boolean) nullArgsResult.get("isError"));

      // Reject non-object arguments and JSON strings decoding to arrays, primitives, or invalid JSON.
      for (Object badArguments :
          List.of("[1, 2]", "123", "true", "\"hello\"", "null", "{invalid", List.of("a"), 42)) {
        HttpResponse<String> badArgResp =
            post(
                client,
                handle.endpoint(),
                Map.of(
                    "jsonrpc",
                    "2.0",
                    "id",
                    3,
                    "method",
                    "tools/call",
                    "params",
                    Map.of("name", "ghidra_address", "arguments", badArguments)));
        assertEquals(200, badArgResp.statusCode());
        Map<String, Object> result =
            (Map<String, Object>)
                ((Map<String, Object>) JsonUtil.parse(badArgResp.body())).get("result");
        assertTrue((Boolean) result.get("isError"));
        Map<String, Object> err = (Map<String, Object>) result.get("structuredContent");
        assertEquals(400L, ((Number) err.get("status")).longValue());
        assertEquals("invalid_type", err.get("code"));
        assertEquals("/arguments", err.get("target"));
      }

      // Reject non-object params and JSON strings decoding to arrays, primitives, or invalid JSON.
      for (Object badParams :
          List.of("[1, 2]", "123", "false", "\"hello\"", "null", "{invalid", List.of("a"), 99)) {
        HttpResponse<String> badParamResp =
            post(
                client,
                handle.endpoint(),
                Map.of(
                    "jsonrpc",
                    "2.0",
                    "id",
                    4,
                    "method",
                    "tools/call",
                    "params",
                    Map.of(
                        "name",
                        "ghidra_address",
                        "arguments",
                        Map.of("operation", "resolve", "params", badParams))));
        assertEquals(200, badParamResp.statusCode());
        Map<String, Object> result =
            (Map<String, Object>)
                ((Map<String, Object>) JsonUtil.parse(badParamResp.body())).get("result");
        assertTrue((Boolean) result.get("isError"));
        Map<String, Object> err = (Map<String, Object>) result.get("structuredContent");
        assertEquals(400L, ((Number) err.get("status")).longValue());
        assertEquals("invalid_type", err.get("code"));
        assertEquals("/params", err.get("target"));
      }

      // Unknown domain tool key lists ["operation", "params"].
      HttpResponse<String> unknownKeyResp =
          post(
              client,
              handle.endpoint(),
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  5,
                  "method",
                  "tools/call",
                  "params",
                  Map.of(
                      "name",
                      "ghidra_address",
                      "arguments",
                      Map.of("operation", "resolve", "extra", 1))));
      assertEquals(200, unknownKeyResp.statusCode());
      Map<String, Object> unknownKeyResult =
          (Map<String, Object>)
              ((Map<String, Object>) JsonUtil.parse(unknownKeyResp.body())).get("result");
      assertTrue((Boolean) unknownKeyResult.get("isError"));
      Map<String, Object> unknownKeyErr =
          (Map<String, Object>) unknownKeyResult.get("structuredContent");
      assertEquals(400L, ((Number) unknownKeyErr.get("status")).longValue());
      assertEquals("unknown_field", unknownKeyErr.get("code"));
      assertEquals("/arguments/extra", unknownKeyErr.get("target"));
      Map<String, Object> details = (Map<String, Object>) unknownKeyErr.get("details");
      assertEquals(List.of("operation", "params"), details.get("allowed_fields"));

      // JsonRpcError (such as unknown operation) is rethrown as 400 -32602, not 500 internal_error.
      HttpResponse<String> unknownOpResp =
          post(
              client,
              handle.endpoint(),
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  6,
                  "method",
                  "tools/call",
                  "params",
                  Map.of(
                      "name",
                      "ghidra_address",
                      "arguments",
                      Map.of("operation", "nonexistent"))));
      assertEquals(400, unknownOpResp.statusCode());
      Map<String, Object> rpcErrorBody =
          (Map<String, Object>) JsonUtil.parse(unknownOpResp.body());
      Map<String, Object> rpcError = (Map<String, Object>) rpcErrorBody.get("error");
      assertEquals(-32602L, ((Number) rpcError.get("code")).longValue());
    }
  }

  private static HttpResponse<String> post(
      HttpClient client, String endpoint, Map<String, Object> payload) throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(payload)))
            .build();
    return client.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private record TestServer(AgentDispatcher dispatcher, McpHttpServer server)
      implements AutoCloseable {
    String endpoint() {
      return server.endpoint();
    }

    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
  }

  private static TestServer startServer(BridgeServices services) throws IOException {
    for (int attempt = 0; attempt < 10; attempt++) {
      int port;
      try (ServerSocket socket = new ServerSocket(0)) {
        port = socket.getLocalPort();
      }
      AgentDispatcher dispatcher =
          new AgentDispatcher(
              services,
              new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "test-session", null));
      try {
        McpConfig config =
            new McpConfig("127.0.0.1", port, "/mcp", null, "test-session", "ghidra");
        McpHttpServer server = new McpHttpServer(config, dispatcher);
        server.start();
        return new TestServer(dispatcher, server);
      } catch (BindException retry) {
        dispatcher.close();
      }
    }
    throw new IOException("unable to allocate ephemeral port for McpHttpServerTest");
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) return null;
          throw new AssertionError(method);
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
