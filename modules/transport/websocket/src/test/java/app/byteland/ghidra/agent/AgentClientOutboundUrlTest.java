package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentClientOutboundUrlTest {

  @Test
  @DisplayName("Omits URISyntaxException causes and unredacted ws_url text in parseOutboundUri")
  void omitsUriSyntaxExceptionCausesAndCredentials() {
    IllegalArgumentException malformedWithUserInfo =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentClient.parseOutboundUri(
                    "ws://marker-user:marker-userinfo-cred@127.0.0.1:8765/ws/agent invalid"));
    assertNull(malformedWithUserInfo.getCause());
    assertDoesNotContainSecret(malformedWithUserInfo, "marker-userinfo-cred");
    assertDoesNotContainSecret(malformedWithUserInfo, "marker-user");

    IllegalArgumentException malformedPercent =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentClient.parseOutboundUri(
                    "ws://127.0.0.1:8765/ws/agent?token=marker-query-cred%ZZ"));
    assertNull(malformedPercent.getCause());
    assertDoesNotContainSecret(malformedPercent, "marker-query-cred");

    IllegalArgumentException userInfoUrl =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AgentClient.parseOutboundUri(
                    "ws://marker-user:marker-userinfo-cred@127.0.0.1:8765/ws/agent?foo=1"));
    assertNull(userInfoUrl.getCause());
    assertDoesNotContainSecret(userInfoUrl, "marker-userinfo-cred");
    assertDoesNotContainSecret(userInfoUrl, "marker-user");
  }

  @Test
  @DisplayName("Matches WebSocketHandshakeValidator rejection for plain and percent-encoded token query parameters")
  void matchesHandshakeValidatorForQueryTokens() {
    AgentConfig serverConfig = AgentConfig.fromArgs("port=8765", "session_id=server-check");
    Map<String, String> validHeaders =
        Map.of(
            "upgrade", "websocket",
            "connection", "Upgrade",
            "sec-websocket-version", "13",
            "sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

    for (String rawQuery : new String[] {"token=marker-query-cred", "%74oken=marker-query-cred"}) {
      WebSocketHandshake.HandshakeRequest request =
          new WebSocketHandshake.HandshakeRequest(
              "GET", "/ws/agent", WebSocketHandshake.parseQuery(rawQuery), validHeaders);
      assertThrows(
          WebSocketHandshake.HttpHandshakeException.class,
          () -> WebSocketHandshakeValidator.validate(serverConfig, request));

      IllegalArgumentException clientEx =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  AgentConfig.fromArgs(
                      "ws_url=ws://127.0.0.1:8765/ws/agent?" + rawQuery,
                      "session_id=outbound-check"));
      assertDoesNotContainSecret(clientEx, "marker-query-cred");

      IllegalArgumentException parseEx =
          assertThrows(
              IllegalArgumentException.class,
              () -> AgentClient.parseOutboundUri("ws://127.0.0.1:8765/ws/agent?" + rawQuery));
      assertDoesNotContainSecret(parseEx, "marker-query-cred");
    }
  }

  @Test
  @DisplayName("Formats outbound connection failures using redactedWsUrl")
  void formatsConnectionFailureWithRedactedWsUrl() throws Exception {
    int unusedPort = findUnusedLoopbackPort("127.0.0.1");
    AgentConfig config =
        AgentConfig.fromArgs(
            "ws_url=ws://127.0.0.1:" + unusedPort + "/ws/agent?foo=marker-query-param",
            "session_id=outbound-fail");

    try (AgentDispatcher dispatcher = new AgentDispatcher(stubBridgeServices(), config)) {
      AgentClient client =
          new AgentClient(
              config, dispatcher, new AgentClient.LifecycleListener() {}, Duration.ofSeconds(2));
      IOException failure = assertThrows(IOException.class, client::connect);
      assertTrue(
          failure
              .getMessage()
              .contains("ws://127.0.0.1:" + unusedPort + "/ws/agent?<redacted>"));
      assertFalse(failure.getMessage().contains("marker-query-param"));
      assertTrue(failure.getCause() != null);
    }
  }

  @Test
  @DisplayName("Preserves HTTP 401 handshake rejection cause when openSession fails")
  void preservesHttp401CauseInOpenSession() throws Exception {
    try (ServerSocket rejectServer = new ServerSocket()) {
      rejectServer.bind(new InetSocketAddress("127.0.0.1", 0));
      int port = rejectServer.getLocalPort();
      Thread responder =
          new Thread(
              () -> {
                while (!rejectServer.isClosed()) {
                  try (var socket = rejectServer.accept()) {
                    WebSocketHandshake.readHandshake(
                        socket, System.nanoTime() + TimeUnit.SECONDS.toNanos(5));
                    WebSocketHandshake.writeHttpResponse(
                        socket.getOutputStream(),
                        401,
                        "Unauthorized",
                        java.util.List.of("Connection: close"),
                        null);
                    WebSocketHandshake.closeAfterHttpError(socket, 250, 8192);
                  } catch (IOException ignored) {
                    if (rejectServer.isClosed()) {
                      break;
                    }
                  }
                }
              });
      responder.setDaemon(true);
      responder.start();

      AgentConfig config =
          AgentConfig.fromArgs(
              "ws_url=ws://127.0.0.1:" + port + "/ws/agent", "session_id=outbound-401");
      try (AgentDispatcher dispatcher = new AgentDispatcher(stubBridgeServices(), config)) {
        AgentClient client =
            new AgentClient(
                config, dispatcher, new AgentClient.LifecycleListener() {}, Duration.ofSeconds(5));
        IOException failure = assertThrows(IOException.class, () -> client.openSession(() -> false));
        assertTrue(failure.getMessage().contains("ws://127.0.0.1:" + port + "/ws/agent"));
        boolean found401 = false;
        for (Throwable cause = failure.getCause(); cause != null; cause = cause.getCause()) {
          if (cause.getMessage() != null && cause.getMessage().contains("401")) {
            found401 = true;
            break;
          }
        }
        assertTrue(found401, "Expected nested cause chain to include HTTP 401 status detail");
      }
    }
  }

  @Test
  @DisplayName("Connects outbound loopback sessions with bearer token over IPv4 and IPv6")
  void connectsOutboundLoopbackSessions() throws Exception {
    verifyLoopbackSession("127.0.0.1", "127.0.0.1");
    if (isIpv6LoopbackAvailable()) {
      verifyLoopbackSession("::1", "[::1]");
    }
  }

  private static void verifyLoopbackSession(String bindHost, String urlHost) throws Exception {
    int port = findUnusedLoopbackPort(bindHost);
    String token = "session-bearer-secret";
    AgentConfig serverConfig =
        new AgentConfig(null, bindHost, port, "/ws/agent", token, "srv-session", null);

    AtomicReference<String> readyPayload = new AtomicReference<>();
    CountDownLatch readyLatch = new CountDownLatch(1);

    try (AgentWebSocketServer server =
        new AgentWebSocketServer(
            serverConfig,
            new AgentWebSocketServer.Handler() {
              @Override
              public void onOpen(AgentWebSocketServer.Connection connection) {}

              @Override
              public void onText(AgentWebSocketServer.Connection connection, String message) {
                readyPayload.set(message);
                readyLatch.countDown();
                connection.close(1000, "done");
              }

              @Override
              public void onClose(
                  AgentWebSocketServer.Connection connection, int statusCode, String reason) {}

              @Override
              public void onConnectionError(
                  AgentWebSocketServer.Connection connection, Throwable error) {}

              @Override
              public void onServerError(Throwable error) {}
            })) {
      server.start();

      AgentConfig outboundConfig =
          AgentConfig.fromArgs(
              "ws_url=ws://" + urlHost + ":" + port + "/ws/agent",
              "token=" + token,
              "session_id=outbound-session");
      assertEquals("ws://" + urlHost + ":" + port + "/ws/agent", outboundConfig.redactedWsUrl());

      try (AgentDispatcher dispatcher =
          new AgentDispatcher(stubBridgeServices(), outboundConfig)) {
        AgentClient client =
            new AgentClient(
                outboundConfig,
                dispatcher,
                new AgentClient.LifecycleListener() {},
                Duration.ofSeconds(5));
        client.connect();
      }

      assertTrue(readyLatch.await(5, TimeUnit.SECONDS));
      assertTrue(readyPayload.get().contains("\"method\":\"ghidra.ready\""));
      assertTrue(readyPayload.get().contains("\"session_id\":\"outbound-session\""));
    }
  }

  private static int findUnusedLoopbackPort(String host) throws IOException {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress(host, 0));
      return socket.getLocalPort();
    }
  }

  private static boolean isIpv6LoopbackAvailable() {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress(InetAddress.getByName("::1"), 0));
      return true;
    } catch (IOException unavailable) {
      return false;
    }
  }

  private static BridgeServices stubBridgeServices() {
    return new BridgeServices(
        proxy(ProgramService.class),
        proxy(AddressService.class),
        proxy(CommentService.class),
        proxy(ReferenceService.class),
        proxy(MemoryService.class),
        proxy(ListingService.class),
        proxy(FunctionService.class),
        proxy(GlobalVariableService.class),
        proxy(AnalysisService.class),
        proxy(DecompilationService.class),
        proxy(SymbolService.class),
        proxy(DataTypeService.class),
        proxy(TransactionRunner.class),
        "test-program");
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> type) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (instance, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              throw new UnsupportedOperationException(method.getName());
            });
  }

  private static void assertDoesNotContainSecret(Throwable error, String secret) {
    StringWriter buffer = new StringWriter();
    error.printStackTrace(new PrintWriter(buffer));
    String fullTrace = buffer.toString();
    assertFalse(
        fullTrace.contains(secret),
        () -> "Expected secret '" + secret + "' to be omitted from exception trace: " + fullTrace);
  }
}
