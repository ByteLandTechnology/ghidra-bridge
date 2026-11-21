package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
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
import app.byteland.ghidra.service.program.ProgramResource;
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
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class McpToolSplitTest {

  @Test
  @SuppressWarnings("unchecked")
  void toolRegistryExposesBoundedReadAndWriteToolsWithDerivedHints() {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog());
    List<Map<String, Object>> tools = registry.listTools();
    assertEquals(26, tools.size());

    List<Map<String, Object>> readOnlyTools =
        tools.stream()
            .filter(tool -> Boolean.TRUE.equals(annotations(tool).get("readOnlyHint")))
            .toList();
    assertEquals(15, readOnlyTools.size());
    for (Map<String, Object> tool : readOnlyTools) {
      assertEquals(Boolean.FALSE, annotations(tool).get("destructiveHint"));
    }

    int readOnlyOperations =
        readOnlyTools.stream()
            .filter(tool -> !"ghidra_help".equals(tool.get("name")))
            .mapToInt(tool -> operations(tool).size())
            .sum();
    assertEquals(29, readOnlyOperations);

    Map<String, Map<String, Object>> byName =
        tools.stream().collect(Collectors.toMap(tool -> tool.get("name").toString(), tool -> tool));
    assertEquals(List.of("query"), operations(byName.get("ghidra_batch")));
    assertEquals(List.of("execute"), operations(byName.get("ghidra_batch_write")));

    assertEquals(Boolean.FALSE, annotations(byName.get("ghidra_program_write")).get("readOnlyHint"));
    assertEquals(
        Boolean.FALSE, annotations(byName.get("ghidra_program_write")).get("destructiveHint"));
    assertEquals(
        Boolean.FALSE, annotations(byName.get("ghidra_analysis_write")).get("readOnlyHint"));
    assertEquals(
        Boolean.FALSE, annotations(byName.get("ghidra_analysis_write")).get("destructiveHint"));

    Set<String> destructiveWriteTools =
        tools.stream()
            .filter(tool -> Boolean.FALSE.equals(annotations(tool).get("readOnlyHint")))
            .filter(tool -> Boolean.TRUE.equals(annotations(tool).get("destructiveHint")))
            .map(tool -> tool.get("name").toString())
            .collect(Collectors.toSet());
    assertEquals(
        Set.of(
            "ghidra_bridge_write",
            "ghidra_memory_write",
            "ghidra_listing_write",
            "ghidra_global_variable_write",
            "ghidra_function_write",
            "ghidra_symbol_write",
            "ghidra_comment_write",
            "ghidra_data_type_write",
            "ghidra_batch_write"),
        destructiveWriteTools);
  }

  @Test
  @SuppressWarnings("unchecked")
  void httpServerRejectsWriteOperationOnReadOnlyToolWithInvalidParamsWithoutDispatching()
      throws Exception {
    AtomicInteger serviceInvocations = new AtomicInteger();
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              serviceInvocations.incrementAndGet();
              if ("getProgram".equals(method)) {
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
              throw new AssertionError("Unexpected ProgramService method: " + method);
            });
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (method, args) -> {
              serviceInvocations.incrementAndGet();
              return new AnalysisResource(
                  AnalysisResource.Kind.GHIDRA,
                  AnalysisResource.Status.IDLE,
                  false,
                  null,
                  null,
                  null,
                  null);
            });
    FunctionService functionService =
        proxy(
            FunctionService.class,
            (method, args) -> {
              serviceInvocations.incrementAndGet();
              throw new AssertionError("FunctionService must not be invoked by read-only tool");
            });
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            serviceInvocations.incrementAndGet();
            throw new AssertionError("TransactionRunner must not be invoked by read-only tool");
          }
        };

    BridgeServices services =
        new BridgeServices(
            programService,
            unused(AddressService.class, serviceInvocations),
            unused(CommentService.class, serviceInvocations),
            unused(ReferenceService.class, serviceInvocations),
            unused(MemoryService.class, serviceInvocations),
            unused(ListingService.class, serviceInvocations),
            functionService,
            unused(GlobalVariableService.class, serviceInvocations),
            analysisService,
            unused(DecompilationService.class, serviceInvocations),
            unused(SymbolService.class, serviceInvocations),
            unused(DataTypeService.class, serviceInvocations),
            transactionRunner,
            "sample.bin");

    int port = freePort();
    AgentConfig agentConfig =
        new AgentConfig("ws://127.0.0.1:9999/ws/agent", null, null, null, null, "s1", null);
    McpConfig mcpConfig = new McpConfig("127.0.0.1", port, "/mcp", null, "s1", "ghidra");
    HttpClient client = HttpClient.newHttpClient();

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, agentConfig);
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher)) {
      server.start();
      URI endpoint = URI.create(server.endpoint());

      // Attempt write operations on read-only tools -> must return HTTP 400 and JSON-RPC -32602.
      for (String[] attempt :
          new String[][] {
            {"ghidra_function", "create"},
            {"ghidra_program", "save"},
            {"ghidra_analysis", "start"},
            {"ghidra_bridge", "shutdown"},
            {"ghidra_batch", "execute"}
          }) {
        HttpResponse<String> rejected =
            post(
                client,
                endpoint,
                Map.of(
                    "jsonrpc",
                    "2.0",
                    "id",
                    "w-" + attempt[0],
                    "method",
                    "tools/call",
                    "params",
                    Map.of(
                        "name",
                        attempt[0],
                        "arguments",
                        Map.of("operation", attempt[1], "params", Map.of()))));
        assertEquals(400, rejected.statusCode(), rejected.body());
        Map<String, Object> body = (Map<String, Object>) JsonUtil.parse(rejected.body());
        Map<String, Object> error = (Map<String, Object>) body.get("error");
        assertNotNull(error, rejected.body());
        assertEquals(-32602, ((Number) error.get("code")).intValue());
      }
      assertEquals(0, serviceInvocations.get(), "AgentDispatcher must not run rejected writes");

      // Read-only call on ghidra_batch with batch.query succeeds and invokes ProgramService.
      HttpResponse<String> batchRead =
          post(
              client,
              endpoint,
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  "r-batch",
                  "method",
                  "tools/call",
                  "params",
                  Map.of(
                      "name",
                      "ghidra_batch",
                      "arguments",
                      Map.of(
                          "operation",
                          "query",
                          "params",
                          Map.of(
                              "items",
                              List.of(
                                  Map.of(
                                      "id",
                                      "prog",
                                      "method",
                                      "program.get",
                                      "arguments",
                                      Map.of())))))));
      assertEquals(200, batchRead.statusCode(), batchRead.body());
      Map<String, Object> okBody = (Map<String, Object>) JsonUtil.parse(batchRead.body());
      Map<String, Object> result = (Map<String, Object>) okBody.get("result");
      assertFalse((Boolean) result.get("isError"), batchRead.body());
      assertTrue(serviceInvocations.get() > 0);
    }
  }

  private static HttpResponse<String> post(HttpClient client, URI uri, Map<String, Object> body)
      throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .header("Content-Type", "application/json")
            .header("MCP-Protocol-Version", "2025-11-25")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(body), StandardCharsets.UTF_8))
            .build();
    return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
  }

  private static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> annotations(Map<String, Object> tool) {
    return (Map<String, Object>) tool.get("annotations");
  }

  @SuppressWarnings("unchecked")
  private static List<String> operations(Map<String, Object> tool) {
    Map<String, Object> schema = (Map<String, Object>) tool.get("inputSchema");
    Map<String, Object> props = (Map<String, Object>) schema.get("properties");
    Map<String, Object> op = (Map<String, Object>) props.get("operation");
    return (List<String>) op.get("enum");
  }

  @FunctionalInterface
  private interface CallHandler {
    Object invoke(String method, Object[] args) throws Exception;
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> type, CallHandler handler) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return method.invoke(handler, args);
              }
              return handler.invoke(method.getName(), args == null ? new Object[0] : args);
            });
  }

  private static <T> T unused(Class<T> type, AtomicInteger invocations) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) return null;
          invocations.incrementAndGet();
          throw new AssertionError("Unexpected service call: " + type.getSimpleName() + "." + method);
        });
  }
}
