package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.BridgeServices;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;

class McpHttpServerPortFallbackTest {

  private static BridgeServices dummyServices() {
    return new BridgeServices(
        proxy(app.byteland.ghidra.service.program.ProgramService.class),
        proxy(app.byteland.ghidra.service.address.AddressService.class),
        proxy(app.byteland.ghidra.service.comment.CommentService.class),
        proxy(app.byteland.ghidra.service.reference.ReferenceService.class),
        proxy(app.byteland.ghidra.service.memory.MemoryService.class),
        proxy(app.byteland.ghidra.service.listing.ListingService.class),
        proxy(app.byteland.ghidra.service.function.FunctionService.class),
        proxy(app.byteland.ghidra.service.globalvariable.GlobalVariableService.class),
        proxy(app.byteland.ghidra.service.analysis.AnalysisService.class),
        proxy(app.byteland.ghidra.service.decompilation.DecompilationService.class),
        proxy(app.byteland.ghidra.service.symbol.SymbolService.class),
        proxy(app.byteland.ghidra.service.datatype.DataTypeService.class),
        proxy(app.byteland.ghidra.service.TransactionRunner.class),
        "demo.bin");
  }

  private static <T> T proxy(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (instance, method, args) -> {
              throw new UnsupportedOperationException(method.getName());
            }));
  }

  private static int reserveEphemeralBasePort() throws Exception {
    try (ServerSocket probe = new ServerSocket()) {
      probe.bind(new InetSocketAddress("127.0.0.1", 0));
      return probe.getLocalPort();
    }
  }

  @Test
  void incrementsLoopbackPortWhenBasePortIsOccupied() throws Exception {
    int basePort = reserveEphemeralBasePort();
    BridgeServices services = dummyServices();
    McpConfig config = new McpConfig("127.0.0.1", basePort, "/mcp", null, "test-a", "ghidra");
    AgentConfig agentConfig =
        new AgentConfig(null, "127.0.0.1", basePort, "/mcp", null, "test-a", null);

    try (AgentDispatcher firstDispatcher = new AgentDispatcher(services, agentConfig, false);
        McpHttpServer first =
            new McpHttpServer(config, firstDispatcher, ignored -> {}, true);
        AgentDispatcher secondDispatcher = new AgentDispatcher(services, agentConfig, false);
        McpHttpServer second =
            new McpHttpServer(config, secondDispatcher, ignored -> {}, true)) {
      first.start();
      second.start();

      assertEquals(basePort, first.port());
      assertTrue(second.port() > first.port());
      assertEquals("http://127.0.0.1:" + second.port() + "/mcp", second.endpoint());

      try (HttpClient client = HttpClient.newHttpClient()) {
        HttpResponse<String> response =
            client.send(
                HttpRequest.newBuilder(URI.create(second.endpoint()))
                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                    .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
      }
    }
  }

  @Test
  void failsWithBindExceptionWhenPortFallbackIsDisabled() throws Exception {
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();
      BridgeServices services = dummyServices();
      McpConfig config = new McpConfig("127.0.0.1", busyPort, "/mcp", null, "test-b", "ghidra");
      AgentConfig agentConfig =
          new AgentConfig(null, "127.0.0.1", busyPort, "/mcp", null, "test-b", null);
      try (AgentDispatcher dispatcher = new AgentDispatcher(services, agentConfig, false)) {
        assertThrows(
            BindException.class,
            () -> new McpHttpServer(config, dispatcher, ignored -> {}, false));
      }
    }
  }
}
