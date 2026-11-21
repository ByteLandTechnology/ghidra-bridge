package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.http.WebSocketHandshakeException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentTransportErrorReportingTest {

  private static BridgeServices dummyServices() {
    Class<?>[] interfaces = {
      app.byteland.ghidra.service.program.ProgramService.class,
      app.byteland.ghidra.service.address.AddressService.class,
      app.byteland.ghidra.service.comment.CommentService.class,
      app.byteland.ghidra.service.reference.ReferenceService.class,
      app.byteland.ghidra.service.memory.MemoryService.class,
      app.byteland.ghidra.service.listing.ListingService.class,
      app.byteland.ghidra.service.function.FunctionService.class,
      app.byteland.ghidra.service.globalvariable.GlobalVariableService.class,
      app.byteland.ghidra.service.analysis.AnalysisService.class,
      app.byteland.ghidra.service.decompilation.DecompilationService.class,
      app.byteland.ghidra.service.symbol.SymbolService.class,
      app.byteland.ghidra.service.datatype.DataTypeService.class,
      app.byteland.ghidra.service.TransactionRunner.class
    };
    Object[] mocks = new Object[interfaces.length];
    for (int i = 0; i < interfaces.length; i++) {
      Class<?> iface = interfaces[i];
      mocks[i] =
          Proxy.newProxyInstance(
              iface.getClassLoader(),
              new Class<?>[] {iface},
              (proxy, method, args) -> {
                if ("close".equals(method.getName())) {
                  return null;
                }
                throw new UnsupportedOperationException(method.getName());
              });
    }
    return new BridgeServices(
        (app.byteland.ghidra.service.program.ProgramService) mocks[0],
        (app.byteland.ghidra.service.address.AddressService) mocks[1],
        (app.byteland.ghidra.service.comment.CommentService) mocks[2],
        (app.byteland.ghidra.service.reference.ReferenceService) mocks[3],
        (app.byteland.ghidra.service.memory.MemoryService) mocks[4],
        (app.byteland.ghidra.service.listing.ListingService) mocks[5],
        (app.byteland.ghidra.service.function.FunctionService) mocks[6],
        (app.byteland.ghidra.service.globalvariable.GlobalVariableService) mocks[7],
        (app.byteland.ghidra.service.analysis.AnalysisService) mocks[8],
        (app.byteland.ghidra.service.decompilation.DecompilationService) mocks[9],
        (app.byteland.ghidra.service.symbol.SymbolService) mocks[10],
        (app.byteland.ghidra.service.datatype.DataTypeService) mocks[11],
        (app.byteland.ghidra.service.TransactionRunner) mocks[12],
        "demo-program");
  }

  private static AgentWebSocketServer.Handler noOpHandler() {
    return new AgentWebSocketServer.Handler() {
      @Override
      public void onOpen(AgentWebSocketServer.Connection connection) {}

      @Override
      public void onText(AgentWebSocketServer.Connection connection, String message) {}

      @Override
      public void onClose(
          AgentWebSocketServer.Connection connection, int statusCode, String reason) {}

      @Override
      public void onConnectionError(
          AgentWebSocketServer.Connection connection, Throwable error) {}

      @Override
      public void onServerError(Throwable error) {}
    };
  }

  @Test
  @DisplayName("WebSocket bind conflict includes full ws:// endpoint and underlying cause")
  void testWebSocketBindConflictIncludesEndpointAndCause() throws Exception {
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", busyPort, "/ws/agent", null, "demo", null);
      try (AgentWebSocketServer server = new AgentWebSocketServer(config, noOpHandler())) {
        BindException thrown = assertThrows(BindException.class, server::start);
        String expectedEndpoint = "ws://127.0.0.1:" + busyPort + "/ws/agent";
        assertTrue(
            thrown.getMessage().contains(expectedEndpoint),
            () -> "Expected endpoint in message, got: " + thrown.getMessage());
        assertNotNull(thrown.getCause());
        assertInstanceOf(BindException.class, thrown.getCause());
        if (thrown.getCause().getMessage() != null && !thrown.getCause().getMessage().isBlank()) {
          assertTrue(thrown.getMessage().contains(thrown.getCause().getMessage()));
        }
      }
    }
  }

  @Test
  @DisplayName("Outbound WebSocket HTTP 401 rejection reports redacted endpoint and 401 cause")
  void testOutboundHttp401ReportsEndpointAndCauseWithoutLeakingSecrets() throws Exception {
    HttpServer rejectingServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    rejectingServer.createContext(
        "/ws/agent",
        exchange -> {
          exchange.sendResponseHeaders(401, -1);
          exchange.close();
        });
    rejectingServer.start();
    int port = rejectingServer.getAddress().getPort();

    String secretToken = "top-secret-bearer-token-98765";
    String querySecret = "query-secret-value-54321";
    String wsUrl = "ws://127.0.0.1:" + port + "/ws/agent?auth=" + querySecret;
    AgentConfig config =
        new AgentConfig(wsUrl, null, null, null, secretToken, "demo-session", null);

    AtomicBoolean connectedCalled = new AtomicBoolean(false);
    try (AgentDispatcher dispatcher = new AgentDispatcher(dummyServices(), config)) {
      AgentClient client =
          new AgentClient(
              config,
              dispatcher,
              new AgentClient.LifecycleListener() {
                @Override
                public void onConnected() {
                  connectedCalled.set(true);
                }
              },
              Duration.ofSeconds(5));

      IOException thrown = assertThrows(IOException.class, client::connect);
      assertFalse(connectedCalled.get(), "onConnected must not run when handshake fails");
      assertTrue(
          thrown.getMessage().contains("ws://127.0.0.1:" + port + "/ws/agent?<redacted>"),
          () -> "Expected redacted endpoint in message, got: " + thrown.getMessage());
      assertTrue(
          thrown.getMessage().contains("401"),
          () -> "Expected HTTP 401 status in message, got: " + thrown.getMessage());
      assertFalse(thrown.getMessage().contains(secretToken), "Bearer token must never leak");
      assertFalse(thrown.getMessage().contains(querySecret), "Query secret must never leak");
      assertInstanceOf(WebSocketHandshakeException.class, thrown.getCause());
    } finally {
      rejectingServer.stop(0);
    }
  }

  @Test
  @DisplayName("Outbound WebSocket connection refused includes ConnectException detail")
  void testOutboundConnectionRefusedIncludesCauseDetail() throws Exception {
    int unusedPort;
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      unusedPort = socket.getLocalPort();
    }

    String wsUrl = "ws://127.0.0.1:" + unusedPort + "/ws/agent";
    AgentConfig config = new AgentConfig(wsUrl, null, null, null, null, "demo-session", null);

    try (AgentDispatcher dispatcher = new AgentDispatcher(dummyServices(), config)) {
      AgentClient client =
          new AgentClient(
              config, dispatcher, new AgentClient.LifecycleListener() {}, Duration.ofSeconds(5));

      IOException thrown = assertThrows(IOException.class, client::connect);
      assertTrue(thrown.getMessage().contains(wsUrl));
      assertNotNull(thrown.getCause());
      assertInstanceOf(ConnectException.class, thrown.getCause());
      assertEquals(
          true,
          thrown.getMessage().contains("ConnectException")
              || thrown.getMessage().toLowerCase().contains("refused"),
          () -> "Expected connection refusal detail in message, got: " + thrown.getMessage());
    }
  }
}
