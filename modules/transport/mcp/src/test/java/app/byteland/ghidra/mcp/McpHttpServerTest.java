package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
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
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class McpHttpServerTest {
  @Test
  void servesDirectOperationCallsAndLegacyDomainCalls() throws Exception {
    AtomicReference<List<Object>> readArgs = new AtomicReference<>();
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("readMemoryRange", method);
              readArgs.set(List.of(args[0], args[1], args[2]));
              return new MemoryResource(
                  "ram:00100000",
                  new ByteSequence(ByteSequence.Encoding.HEX, "7f454c46", 4));
            });
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                "close".equals(method)
                    ? null
                    : new AnalysisResource(
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
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            memory,
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactions,
            "sample.bin");

    int port = freeLoopbackPort();
    McpConfig config = new McpConfig("127.0.0.1", port, "/mcp", null, "demo", "ghidra");
    try (AgentDispatcher dispatcher =
            new AgentDispatcher(
                services, new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "demo", null));
        McpHttpServer server = new McpHttpServer(config, dispatcher)) {
      server.start();
      HttpClient client = HttpClient.newHttpClient();
      URI endpoint = URI.create(server.endpoint());

      Map<?, ?> listed = postJsonRpc(client, endpoint, Map.of(
          "jsonrpc", "2.0",
          "id", "list-1",
          "method", "tools/list",
          "params", Map.of()));
      List<?> tools = (List<?>) ((Map<?, ?>) listed.get("result")).get("tools");
      assertEquals(56, tools.size());

      Map<?, ?> directCall = postJsonRpc(client, endpoint, Map.of(
          "jsonrpc", "2.0",
          "id", "call-direct",
          "method", "tools/call",
          "params", Map.of(
              "name", "ghidra_memory_read",
              "arguments", Map.of(
                  "selector", Map.of("address", "ram:00100000"),
                  "length", 4))));
      Map<?, ?> directResult = (Map<?, ?>) directCall.get("result");
      assertEquals(Boolean.FALSE, directResult.get("isError"));
      Map<?, ?> directContent = (Map<?, ?>) directResult.get("structuredContent");
      assertEquals("ram:00100000", directContent.get("address"));
      assertFalse(directContent.containsKey("operation"));
      assertEquals(List.of("ram:00100000", 4, ByteSequence.Encoding.HEX), readArgs.get());

      Map<?, ?> legacyCall = postJsonRpc(client, endpoint, Map.of(
          "jsonrpc", "2.0",
          "id", "call-legacy",
          "method", "tools/call",
          "params", Map.of(
              "name", "ghidra_memory",
              "arguments", Map.of(
                  "operation", "read",
                  "params", Map.of(
                      "selector", Map.of("address", "ram:00100004"),
                      "length", 4)))));
      Map<?, ?> legacyResult = (Map<?, ?>) legacyCall.get("result");
      assertEquals(Boolean.FALSE, legacyResult.get("isError"));
      Map<?, ?> legacyContent = (Map<?, ?>) legacyResult.get("structuredContent");
      assertEquals("read", legacyContent.get("operation"));
      assertEquals("ram:00100000", ((Map<?, ?>) legacyContent.get("result")).get("address"));
      assertEquals(List.of("ram:00100004", 4, ByteSequence.Encoding.HEX), readArgs.get());

      Map<?, ?> helpCall = postJsonRpc(client, endpoint, Map.of(
          "jsonrpc", "2.0",
          "id", "call-help",
          "method", "tools/call",
          "params", Map.of("name", "ghidra_help", "arguments", Map.of())));
      Map<?, ?> helpResult = (Map<?, ?>) helpCall.get("result");
      assertEquals(Boolean.FALSE, helpResult.get("isError"));
      List<?> domains = (List<?>) ((Map<?, ?>) helpResult.get("structuredContent")).get("domains");
      assertTrue(domains.contains("ghidra_memory"));
    }
  }

  private static Map<?, ?> postJsonRpc(HttpClient client, URI uri, Map<String, Object> body)
      throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2025-11-25")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(body)))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode(), response.body());
    return (Map<?, ?>) JsonUtil.parse(response.body());
  }

  private static int freeLoopbackPort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
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
