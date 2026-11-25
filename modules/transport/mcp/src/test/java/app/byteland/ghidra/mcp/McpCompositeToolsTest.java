package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.ControlFlowGraphResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.listing.ListingWindowResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceContextResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpCompositeToolsTest {

  @Test
  void mapsCompositeMethodsIntoDomainToolsHelpAndHttpServer() throws Exception {
    McpToolRegistry registry = new McpToolRegistry(ApiRegistry.catalog(), "ghidra");
    List<Map<String, Object>> tools = registry.listTools();

    assertTrue(operationEnum(tools, "ghidra_listing").contains("window.get"));
    assertTrue(operationEnum(tools, "ghidra_function").contains("control_flow_graph.get"));
    assertTrue(operationEnum(tools, "ghidra_reference").contains("context.list"));

    MethodDescriptor windowDesc = registry.findTool("ghidra_listing", "window.get");
    assertNotNull(windowDesc);
    assertEquals("listing_window.get", windowDesc.name());

    MethodDescriptor cfgDesc = registry.findTool("ghidra_function", "control_flow_graph.get");
    assertNotNull(cfgDesc);
    assertEquals("control_flow_graph.get", cfgDesc.name());

    MethodDescriptor refDesc = registry.findTool("ghidra_reference", "context.list");
    assertNotNull(refDesc);
    assertEquals("reference_context.list", refDesc.name());

    Map<String, Object> helpDoc =
        registry.help(Map.of("domain", "ghidra_function", "operation", "control_flow_graph.get"));
    assertEquals("ghidra_function", helpDoc.get("domain"));
    assertEquals("control_flow_graph.get", helpDoc.get("operation"));
    assertEquals("control_flow_graph.get", helpDoc.get("method"));

    int port = reserveLoopbackPort();
    try (AgentDispatcher dispatcher = createDispatcher();
        McpHttpServer server =
            new McpHttpServer(
                new McpConfig("127.0.0.1", port, "/mcp", null, "test", "ghidra"), dispatcher)) {
      server.start();
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

      Map<String, Object> windowRes =
          callTool(
              client,
              server.endpoint(),
              "ghidra_listing",
              Map.of("operation", "window.get", "params", Map.of("page", Map.of("limit", 20))));
      assertEquals("window.get", structured(windowRes).get("operation"));

      Map<String, Object> cfgRes =
          callTool(
              client,
              server.endpoint(),
              "ghidra_function",
              Map.of(
                  "operation",
                  "control_flow_graph.get",
                  "params",
                  Map.of("selector", Map.of("entry", "ram:00401000"))));
      assertEquals("control_flow_graph.get", structured(cfgRes).get("operation"));

      Map<String, Object> refRes =
          callTool(
              client,
              server.endpoint(),
              "ghidra_reference",
              Map.of(
                  "operation",
                  "context.list",
                  "params",
                  Map.of("filter", Map.of("to", "ram:00401000"))));
      assertEquals("context.list", structured(refRes).get("operation"));
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> structured(Map<String, Object> rpcResponse) {
    Map<String, Object> result = (Map<String, Object>) rpcResponse.get("result");
    assertEquals(Boolean.FALSE, result.get("isError"));
    return (Map<String, Object>) result.get("structuredContent");
  }

  private static Map<String, Object> callTool(
      HttpClient client, String endpoint, String toolName, Map<String, Object> arguments)
      throws IOException, InterruptedException {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put(
        "_meta",
        Map.of(
            "io.modelcontextprotocol/protocolVersion", "2026-07-28",
            "io.modelcontextprotocol/clientInfo", Map.of("name", "mcp-test", "version", "1.0.0"),
            "io.modelcontextprotocol/clientCapabilities", Map.of()));
    params.put("name", toolName);
    params.put("arguments", arguments);

    Map<String, Object> requestBody = new LinkedHashMap<>();
    requestBody.put("jsonrpc", "2.0");
    requestBody.put("id", "req-1");
    requestBody.put("method", "tools/call");
    requestBody.put("params", params);

    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint))
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

  private static int reserveLoopbackPort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      return socket.getLocalPort();
    }
  }

  @SuppressWarnings("unchecked")
  private static List<String> operationEnum(List<Map<String, Object>> tools, String name) {
    Map<String, Object> tool =
        tools.stream()
            .filter(candidate -> name.equals(candidate.get("name")))
            .findFirst()
            .orElseThrow();
    Map<String, Object> inputSchema = (Map<String, Object>) tool.get("inputSchema");
    Map<String, Object> properties = (Map<String, Object>) inputSchema.get("properties");
    Map<String, Object> operation = (Map<String, Object>) properties.get("operation");
    return (List<String>) operation.get("enum");
  }

  private static AgentDispatcher createDispatcher() {
    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) ->
                new ListingWindowResource(
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    null,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        null,
                        null,
                        null,
                        null,
                        true,
                        ScanProgress.StopReason.COMPLETED,
                        1L)));
    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) ->
                new ControlFlowGraphResource(
                    "ram:00401000",
                    "main",
                    "Global",
                    null,
                    null,
                    false,
                    0,
                    List.of(),
                    List.of(),
                    List.of(),
                    null));
    ReferenceService references =
        proxy(
            ReferenceService.class,
            (method, args) ->
                Page.scanned(
                    List.<ReferenceContextResource>of(),
                    100,
                    null,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        "ram:00401000",
                        "ram:00401000",
                        null,
                        null,
                        true,
                        ScanProgress.StopReason.COMPLETED,
                        1L)));
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) -> {
              if ("close".equals(method)) return null;
              return new AnalysisResource(
                  AnalysisResource.Kind.GHIDRA,
                  AnalysisResource.Status.IDLE,
                  false,
                  null,
                  null,
                  null,
                  null);
            });
    DecompilationService decompilation =
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
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            references,
            unused(MemoryService.class),
            listing,
            functions,
            unused(GlobalVariableService.class),
            analysis,
            decompilation,
            unused(SymbolService.class),
            unused(DataTypeService.class),
            tx,
            "test");
    return new AgentDispatcher(
        services, new AgentConfig(null, "127.0.0.1", 8765, "/ws/agent", null, "test", null));
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("Unexpected method: " + method);
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
