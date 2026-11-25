package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(value = 30, unit = TimeUnit.SECONDS)
class WebSocketEnvelopeAndSendErrorTest {

  private static final String REQ_NULL_PARAM =
      "{\"jsonrpc\":\"2.0\",\"id\":\"req-null-param\",\"method\":\"program.get\",\"params\":{\"projection\":null}}";
  private static final String NOTIF_NULL_PARAM =
      "{\"jsonrpc\":\"2.0\",\"method\":\"program.get\",\"params\":{\"projection\":null}}";
  private static final String ERR_BLANK =
      "{\"jsonrpc\":\"2.0\",\"id\":\"err-blank\",\"error\":{\"code\":-32000,\"message\":\"   \"}}";
  private static final String ERR_NULL_DATA =
      "{\"jsonrpc\":\"2.0\",\"id\":\"err-null-data\",\"error\":{\"code\":-32000,\"message\":\"bad\",\"data\":null}}";
  private static final String ERR_DATA_ENTRY =
      "{\"jsonrpc\":\"2.0\",\"id\":\"err-data-entry\",\"error\":{\"code\":-32000,\"message\":\"bad\",\"data\":{\"target\":null}}}";
  private static final String FOLLOWUP_SESSION_GET =
      "{\"jsonrpc\":\"2.0\",\"id\":\"followup-1\",\"method\":\"session.get\",\"params\":{}}";

  @Test
  @DisplayName("MessageEnvelope preserves null values in unmodifiable maps and validates RpcError")
  void testMessageEnvelopeValidationAndNullValueCopies() {
    Map<String, Object> rawParams = new LinkedHashMap<>();
    rawParams.put("projection", null);
    rawParams.put("limit", 10);

    var request = new MessageEnvelope.Request("req-1", "program.get", rawParams);
    assertTrue(request.params().containsKey("projection"));
    assertNull(request.params().get("projection"));
    assertEquals(List.of("projection", "limit"), List.copyOf(request.params().keySet()));
    assertThrows(
        UnsupportedOperationException.class, () -> request.params().put("extra", "rejected"));

    var notification = new MessageEnvelope.Notification("program.get", rawParams);
    assertTrue(notification.params().containsKey("projection"));
    assertNull(notification.params().get("projection"));
    assertThrows(
        UnsupportedOperationException.class, () -> notification.params().put("extra", "rejected"));

    Map<String, Object> rawData = new LinkedHashMap<>();
    rawData.put("target", null);
    var rpcError = new MessageEnvelope.RpcError(-32000, "bad", rawData);
    assertTrue(rpcError.data().containsKey("target"));
    assertNull(rpcError.data().get("target"));
    assertThrows(
        UnsupportedOperationException.class, () -> rpcError.data().put("extra", "rejected"));

    assertThrows(ApiException.class, () -> new MessageEnvelope.RpcError(-32000, null, Map.of()));
    assertThrows(ApiException.class, () -> new MessageEnvelope.RpcError(-32000, "   ", Map.of()));

    for (String invalidJson :
        List.of(
            ERR_BLANK,
            ERR_NULL_DATA,
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-str-data\",\"error\":{\"code\":-32000,\"message\":\"bad\",\"data\":\"text\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-arr-data\",\"error\":{\"code\":-32000,\"message\":\"bad\",\"data\":[]}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-float-code\",\"error\":{\"code\":-32000.5,\"message\":\"bad\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-exp-code\",\"error\":{\"code\":1e3,\"message\":\"bad\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-overflow-code\",\"error\":{\"code\":9223372036854775807,\"message\":\"bad\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-str-code\",\"error\":{\"code\":\"-32000\",\"message\":\"bad\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-null-code\",\"error\":{\"code\":null,\"message\":\"bad\"}}",
            "{\"jsonrpc\":\"2.0\",\"id\":\"err-null-msg\",\"error\":{\"code\":-32000,\"message\":null}}")) {
      Map<String, Object> raw = JsonUtil.parseObject(invalidJson);
      assertThrows(ApiException.class, () -> MessageEnvelope.fromMap(raw), invalidJson);
    }

    MessageEnvelope validErrorEnvelope =
        MessageEnvelope.fromMap(JsonUtil.parseObject(ERR_DATA_ENTRY));
    assertTrue(validErrorEnvelope instanceof MessageEnvelope.Response);
    MessageEnvelope.Response errorResponse = (MessageEnvelope.Response) validErrorEnvelope;
    assertEquals("err-data-entry", errorResponse.id());
    assertEquals(-32000, errorResponse.error().code());
    assertTrue(errorResponse.error().data().containsKey("target"));
    assertNull(errorResponse.error().data().get("target"));
  }

  @Test
  @DisplayName("Inbound server mode keeps WebSocket open across malformed and null-value envelopes")
  void testInboundServerModeKeepsConnectionOpen() throws Exception {
    AtomicBoolean cancel = new AtomicBoolean(false);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    StartedInboundAgent started = startInboundAgent(executor, cancel);
    boolean serverStopped = false;

    try {
      BlockingQueue<String> incoming = new LinkedBlockingQueue<>();
      AtomicBoolean closed = new AtomicBoolean(false);
      CountDownLatch closeLatch = new CountDownLatch(1);
      try (HttpClient httpClient =
          HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()) {
        WebSocket clientSocket =
            httpClient
                .newWebSocketBuilder()
                .buildAsync(
                    URI.create("ws://127.0.0.1:" + started.port() + "/ws/agent"),
                    new QueueWebSocketListener(incoming, closed, closeLatch))
                .get(5, TimeUnit.SECONDS);
        boolean closeHandshakeComplete = false;
        try {
          assertReadyNotification(incoming.poll(5, TimeUnit.SECONDS), "inbound-session");

          sendClientText(clientSocket, REQ_NULL_PARAM);
          Map<String, Object> nullParamErr =
              assertMethodError(
                  incoming.poll(5, TimeUnit.SECONDS), "req-null-param", "invalid_type");
          assertEquals("/projection", nullParamErr.get("target"));

          sendClientText(clientSocket, NOTIF_NULL_PARAM);

          sendClientText(clientSocket, ERR_BLANK);
          assertProtocolError(incoming.poll(5, TimeUnit.SECONDS), -32600);

          sendClientText(clientSocket, ERR_NULL_DATA);
          assertProtocolError(incoming.poll(5, TimeUnit.SECONDS), -32600);

          sendClientText(clientSocket, ERR_DATA_ENTRY);

          // Check nullable schema fields on the same socket.
          sendClientText(
              clientSocket,
              "{\"jsonrpc\":\"2.0\",\"id\":\"req-nullable-comment\",\"method\":\"function.patch\",\"params\":{\"selector\":{\"entry\":\"ram:00100000\"},\"patch\":{\"comment\":null}}}");
          Map<String, Object> patchReply =
              JsonUtil.parseObject(incoming.poll(5, TimeUnit.SECONDS));
          assertEquals("req-nullable-comment", patchReply.get("id"));
          @SuppressWarnings("unchecked")
          Map<String, Object> patchResult = (Map<String, Object>) patchReply.get("result");
          assertNotNull(patchResult);
          assertEquals("ram:00100000", patchResult.get("entry"));

          sendClientText(clientSocket, FOLLOWUP_SESSION_GET);
          assertSessionFollowup(incoming.poll(5, TimeUnit.SECONDS), "inbound-session");
          assertFalse(closed.get());
          assertNull(incoming.poll(100, TimeUnit.MILLISECONDS));

          clientSocket.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(5, TimeUnit.SECONDS);
          assertTrue(closeLatch.await(5, TimeUnit.SECONDS));
          closeHandshakeComplete = true;
        } finally {
          if (!closeHandshakeComplete) {
            clientSocket.abort();
          }
        }
      }
      cancel.set(true);
      started.serverFuture().get(5, TimeUnit.SECONDS);
      serverStopped = true;
    } finally {
      cancel.set(true);
      if (!serverStopped) {
        disconnectQuietly(started.agentClient());
      }
      closeQuietly(started.dispatcher());
      executor.shutdownNow();
    }
  }

  @Test
  @DisplayName("Outbound ws_url mode keeps WebSocket open across malformed and null-value envelopes")
  void testOutboundWsUrlModeKeepsConnectionOpen() throws Exception {
    BlockingQueue<String> hostIncoming = new LinkedBlockingQueue<>();
    AtomicReference<AgentWebSocketServer.Connection> hostConnectionRef = new AtomicReference<>();
    CountDownLatch peerConnected = new CountDownLatch(1);
    CountDownLatch peerCloseLatch = new CountDownLatch(1);
    AtomicBoolean peerClosed = new AtomicBoolean(false);
    AgentWebSocketServer.Handler hostHandler =
        new AgentWebSocketServer.Handler() {
          @Override
          public void onOpen(AgentWebSocketServer.Connection connection) {
            hostConnectionRef.set(connection);
            peerConnected.countDown();
          }

          @Override
          public void onText(AgentWebSocketServer.Connection connection, String message) {
            hostIncoming.offer(message);
          }

          @Override
          public void onClose(
              AgentWebSocketServer.Connection connection, int statusCode, String reason) {
            peerClosed.set(true);
            peerCloseLatch.countDown();
          }

          @Override
          public void onConnectionError(
              AgentWebSocketServer.Connection connection, Throwable error) {
            peerCloseLatch.countDown();
          }

          @Override
          public void onServerError(Throwable error) {}
        };

    AtomicBoolean cancel = new AtomicBoolean(false);
    ExecutorService executor = Executors.newSingleThreadExecutor();

    try (StartedHostServer startedHost = startHostServer(hostHandler)) {
      AgentConfig outboundConfig =
          new AgentConfig(
              "ws://127.0.0.1:" + startedHost.port() + "/ws/agent",
              null,
              null,
              null,
              null,
              "outbound-session",
              null);
      try (AgentDispatcher dispatcher = testDispatcher(outboundConfig, null)) {
        AgentClient agentClient =
            new AgentClient(
                outboundConfig,
                dispatcher,
                new AgentClient.LifecycleListener() {},
                Duration.ofSeconds(5));
        Future<?> clientFuture =
            executor.submit(
                () -> {
                  agentClient.connect(cancel::get);
                  return null;
                });
        boolean clientStopped = false;

        try {
          assertTrue(peerConnected.await(5, TimeUnit.SECONDS));
          assertReadyNotification(hostIncoming.poll(5, TimeUnit.SECONDS), "outbound-session");
          AgentWebSocketServer.Connection hostConnection = hostConnectionRef.get();
          assertNotNull(hostConnection);

          hostConnection.sendText(REQ_NULL_PARAM);
          Map<String, Object> nullParamErr =
              assertMethodError(
                  hostIncoming.poll(5, TimeUnit.SECONDS), "req-null-param", "invalid_type");
          assertEquals("/projection", nullParamErr.get("target"));

          hostConnection.sendText(NOTIF_NULL_PARAM);

          hostConnection.sendText(ERR_BLANK);
          assertProtocolError(hostIncoming.poll(5, TimeUnit.SECONDS), -32600);

          hostConnection.sendText(ERR_NULL_DATA);
          assertProtocolError(hostIncoming.poll(5, TimeUnit.SECONDS), -32600);

          hostConnection.sendText(ERR_DATA_ENTRY);

          // Check nullable schema fields in outbound mode as well.
          hostConnection.sendText(
              "{\"jsonrpc\":\"2.0\",\"id\":\"req-nullable-comment\",\"method\":\"function.patch\",\"params\":{\"selector\":{\"entry\":\"ram:00100000\"},\"patch\":{\"comment\":null}}}");
          Map<String, Object> patchReply =
              JsonUtil.parseObject(hostIncoming.poll(5, TimeUnit.SECONDS));
          assertEquals("req-nullable-comment", patchReply.get("id"));
          @SuppressWarnings("unchecked")
          Map<String, Object> patchResult = (Map<String, Object>) patchReply.get("result");
          assertNotNull(patchResult);
          assertEquals("ram:00100000", patchResult.get("entry"));

          hostConnection.sendText(FOLLOWUP_SESSION_GET);
          assertSessionFollowup(hostIncoming.poll(5, TimeUnit.SECONDS), "outbound-session");
          assertFalse(peerClosed.get());
          assertNull(hostIncoming.poll(100, TimeUnit.MILLISECONDS));

          cancel.set(true);
          clientFuture.get(5, TimeUnit.SECONDS);
          clientStopped = true;
          assertTrue(peerCloseLatch.await(5, TimeUnit.SECONDS));
        } finally {
          cancel.set(true);
          if (!clientStopped) {
            disconnectQuietly(agentClient);
          }
        }
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  @DisplayName("AgentMessageHandler isolates RuntimeException to -32600 and propagates send errors")
  void testMessageHandlerIsolatesRuntimeExceptionFromSendErrors() {
    AgentConfig config =
        new AgentConfig("ws://127.0.0.1:9999/ws/agent", null, null, null, null, "unit-s", null);
    AtomicBoolean disconnected = new AtomicBoolean(false);
    List<String> sent = new ArrayList<>();
    AgentClientChannels.MessageChannel recordingChannel =
        new AgentClientChannels.MessageChannel() {
          @Override
          public void sendText(String message) {
            sent.add(message);
          }

          @Override
          public void close() {}

          @Override
          public void close(int code, String reason) {}
        };

    try (AgentDispatcher dispatcher = testDispatcher(config, null)) {
      AgentMessageHandler handler =
          new AgentMessageHandler(config, dispatcher, () -> disconnected.set(true));

      // Check that invalid JSON returns -32700 parse_error without disconnect.
      handler.handleMessage(recordingChannel, "{bad json");
      assertEquals(1, sent.size());
      assertProtocolError(sent.removeFirst(), -32700);
      assertFalse(disconnected.get());

      // Check that an unexpected RuntimeException in envelope decode returns -32600.
      Map<String, Object> brokenMap =
          new java.util.AbstractMap<>() {
            @Override
            public java.util.Set<Entry<String, Object>> entrySet() {
              throw new UnsupportedOperationException("corrupted map view");
            }
          };
      handler.handleParsed(recordingChannel, brokenMap);
      assertEquals(1, sent.size());
      assertProtocolError(sent.removeFirst(), -32600);
      assertFalse(disconnected.get());

      // Check that a raw map with non-text keys throws ApiException.
      Map<Object, Object> untyped = new HashMap<>();
      untyped.put(42, "bad-key");
      @SuppressWarnings("unchecked")
      Map<String, Object> badMap = (Map<String, Object>) (Map<?, ?>) untyped;
      assertThrows(ApiException.class, () -> MessageEnvelope.fromMap(badMap));

      // Check that ChannelSendException propagates out of handleMessage without a second send.
      AtomicInteger sendAttempts = new AtomicInteger();
      AgentClientChannels.MessageChannel failingChannel =
          new AgentClientChannels.MessageChannel() {
            @Override
            public void sendText(String message) {
              sendAttempts.incrementAndGet();
              throw new AgentClientChannels.ChannelSendException(
                  "broken pipe", new IOException("broken pipe"));
            }

            @Override
            public void close() {}

            @Override
            public void close(int code, String reason) {}
          };

      assertThrows(
          AgentClientChannels.ChannelSendException.class,
          () -> handler.handleMessage(failingChannel, ERR_BLANK));
      assertEquals(1, sendAttempts.get());
      assertFalse(disconnected.get());
    }
  }

  @Test
  @DisplayName("AgentClientWebSocketListener aborts WebSocket only on transport send failures")
  void testListenerAbortsOnlyOnTransportSendFailures() {
    AgentConfig config =
        new AgentConfig("ws://127.0.0.1:9999/ws/agent", null, null, null, null, "listener-s", null);
    try (AgentDispatcher dispatcher = testDispatcher(config, null)) {
      AgentMessageHandler messageHandler = new AgentMessageHandler(config, dispatcher, () -> {});

      FakeWebSocket healthySocket = new FakeWebSocket(null);
      AtomicReference<AgentClientChannels.MessageChannel> channelRef =
          new AtomicReference<>(AgentClientChannels.outbound(healthySocket));
      CountDownLatch disconnectLatch = new CountDownLatch(1);
      AgentClientWebSocketListener listener =
          new AgentClientWebSocketListener(channelRef, disconnectLatch, messageHandler);

      listener.onText(healthySocket, ERR_BLANK, true);
      assertEquals(0, healthySocket.abortCalls.get());
      assertEquals(1, healthySocket.requestCalls.get());
      assertEquals(1L, disconnectLatch.getCount());
      assertNotNull(channelRef.get());
      assertEquals(1, healthySocket.sentTexts.size());
      assertProtocolError(healthySocket.sentTexts.getFirst(), -32600);

      // Simulate an outbound send failure and check abort and disconnect.
      FakeWebSocket brokenSocket =
          new FakeWebSocket(CompletableFuture.failedFuture(new IOException("connection reset")));
      AtomicReference<AgentClientChannels.MessageChannel> brokenChannelRef =
          new AtomicReference<>(AgentClientChannels.outbound(brokenSocket));
      CountDownLatch brokenLatch = new CountDownLatch(1);
      AgentClientWebSocketListener brokenListener =
          new AgentClientWebSocketListener(brokenChannelRef, brokenLatch, messageHandler);

      brokenListener.onText(brokenSocket, FOLLOWUP_SESSION_GET, true);
      assertTrue(brokenSocket.abortCalls.get() >= 1);
      assertEquals(0, brokenSocket.requestCalls.get());
      assertEquals(0L, brokenLatch.getCount());
      assertNull(brokenChannelRef.get());
    }
  }

  @Test
  @DisplayName("Outbound AgentClient.connect does not block in HttpClient.close after send error")
  void testOutboundClientCloseDoesNotHangWhenPeerResetsDuringReply() throws Exception {
    CountDownLatch dispatchEntered = new CountDownLatch(1);
    CountDownLatch releaseDispatch = new CountDownLatch(1);

    try (ServerSocket rawServer = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      rawServer.setSoTimeout(5_000);
      int port = rawServer.getLocalPort();
      AgentConfig outboundConfig =
          new AgentConfig(
              "ws://127.0.0.1:" + port + "/ws/agent",
              null,
              null,
              null,
              null,
              "abort-session",
              null);

      ExecutorService peerExecutor = Executors.newSingleThreadExecutor();
      ExecutorService clientExecutor = Executors.newSingleThreadExecutor();
      try (AgentDispatcher dispatcher =
          testDispatcher(
              outboundConfig,
              () -> {
                dispatchEntered.countDown();
                try {
                  releaseDispatch.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                }
              })) {
        Future<?> peerFuture =
            peerExecutor.submit(
                () -> {
                  try (Socket peer = rawServer.accept()) {
                    peer.setTcpNoDelay(true);
                    WebSocketHandshake.HandshakeRequest handshake =
                        WebSocketHandshake.readHandshake(
                            peer, System.nanoTime() + TimeUnit.SECONDS.toNanos(5));
                    WebSocketHandshake.writeHandshakeResponse(
                        peer.getOutputStream(), handshake.acceptKey());
                    peer.setSoTimeout(5_000);
                    // Read the masked ready frame from the outbound AgentClient.
                    WebSocketFrames.Frame readyFrame =
                        WebSocketFrames.readFrame(peer.getInputStream());
                    assertEquals(WebSocketFrames.TEXT_OPCODE, readyFrame.opcode());
                    // Use an ID larger than the 16 KiB JDK WebSocket buffer.
                    // The reply then flushes across buffers to the reset socket and fails fast.
                    String largeId = "req-rst-" + "x".repeat(20_000);
                    byte[] requestBytes =
                        ("{\"jsonrpc\":\"2.0\",\"id\":\""
                                + largeId
                                + "\",\"method\":\"program.save\",\"params\":{}}")
                            .getBytes(StandardCharsets.UTF_8);
                    WebSocketFrames.writeFrame(
                        peer.getOutputStream(), WebSocketFrames.TEXT_OPCODE, requestBytes);
                    assertTrue(dispatchEntered.await(5, TimeUnit.SECONDS));
                    peer.setSoLinger(true, 0);
                  } finally {
                    releaseDispatch.countDown();
                  }
                  return null;
                });

        AgentClient agentClient =
            new AgentClient(
                outboundConfig,
                dispatcher,
                new AgentClient.LifecycleListener() {},
                Duration.ofSeconds(5));
        Future<?> connectFuture =
            clientExecutor.submit(
                () -> {
                  agentClient.connect();
                  return null;
                });

        peerFuture.get(5, TimeUnit.SECONDS);
        // Complete without a block in HttpClient.close().
        connectFuture.get(10, TimeUnit.SECONDS);
      } finally {
        peerExecutor.shutdownNow();
        clientExecutor.shutdownNow();
      }
    }
  }

  private static AgentDispatcher testDispatcher(AgentConfig config, Runnable onSaveHook) {
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("saveProgram".equals(method)) {
                if (onSaveHook != null) onSaveHook.run();
                return null;
              }
              throw new UnsupportedOperationException(method);
            });
    FunctionService functionService =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if ("patchFunction".equals(method)) {
                return null;
              }
              if ("getFunction".equals(method)) {
                return new FunctionResource(
                    "ram:00100000", "test_function", null, null, null, null, null, 0, null, null,
                    null, null, false, false, false, false, null, false, false, null, null, null);
              }
              throw new UnsupportedOperationException(method);
            });
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (method, args) -> {
              if ("close".equals(method)) return null;
              return new AnalysisResource(
                  AnalysisResource.Kind.GHIDRA, AnalysisResource.Status.IDLE, false, null, null,
                  null, null, null, null);
            });
    DecompilationService decompilationService =
        proxy(
            DecompilationService.class,
            (method, args) -> {
              if ("close".equals(method)) return null;
              throw new UnsupportedOperationException(method);
            });
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException runtime) {
              throw runtime;
            } catch (Exception checked) {
              throw new IllegalStateException(checked);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            programService, unused(AddressService.class), unused(CommentService.class),
            unused(ReferenceService.class), unused(MemoryService.class),
            unused(ListingService.class), functionService, unused(GlobalVariableService.class),
            analysisService, decompilationService, unused(SymbolService.class),
            unused(DataTypeService.class), transactionRunner, "test.bin");
    return new AgentDispatcher(services, config);
  }

  private interface InvocationHandlerFn {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new UnsupportedOperationException(method);
        });
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> type, InvocationHandlerFn fn) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxyInstance, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> type.getSimpleName() + "Proxy";
                  case "hashCode" -> System.identityHashCode(proxyInstance);
                  case "equals" -> proxyInstance == args[0];
                  default -> null;
                };
              }
              return fn.invoke(method.getName(), args);
            });
  }

  private static int freeLoopbackPort() throws IOException {
    try (ServerSocket socket = new ServerSocket()) {
      socket.setReuseAddress(true);
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      return socket.getLocalPort();
    }
  }

  private record StartedInboundAgent(
      AgentClient agentClient, AgentDispatcher dispatcher, Future<?> serverFuture, int port) {}

  private record StartedHostServer(AgentWebSocketServer server, int port) implements AutoCloseable {
    @Override
    public void close() {
      server.close();
    }
  }

  private static StartedInboundAgent startInboundAgent(
      ExecutorService executor, AtomicBoolean cancel) throws Exception {
    for (int attempt = 0; attempt < 5; attempt++) {
      int port = freeLoopbackPort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "inbound-session", null);
      AgentDispatcher dispatcher = testDispatcher(config, null);
      CountDownLatch listening = new CountDownLatch(1);
      AgentClient agentClient =
          new AgentClient(
              config,
              dispatcher,
              new AgentClient.LifecycleListener() {
                @Override
                public void onListening() {
                  listening.countDown();
                }
              },
              Duration.ofSeconds(5));
      Future<?> serverFuture =
          executor.submit(
              () -> {
                agentClient.connect(cancel::get);
                return null;
              });
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (System.nanoTime() < deadline) {
        if (listening.await(20, TimeUnit.MILLISECONDS)) {
          return new StartedInboundAgent(agentClient, dispatcher, serverFuture, port);
        }
        if (serverFuture.isDone()) {
          break;
        }
      }
      disconnectQuietly(agentClient);
      closeQuietly(dispatcher);
      try {
        serverFuture.get(1, TimeUnit.SECONDS);
      } catch (ExecutionException failure) {
        if (failure.getCause() instanceof BindException && attempt < 4) {
          continue;
        }
        throw failure;
      }
      throw new AssertionError("Timed out before inbound AgentClient reached onListening");
    }
    throw new IllegalStateException("Failed to start inbound AgentClient");
  }

  private static StartedHostServer startHostServer(AgentWebSocketServer.Handler handler)
      throws IOException {
    for (int attempt = 0; attempt < 5; attempt++) {
      int port = freeLoopbackPort();
      AgentConfig hostServerConfig =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "host-listener", null);
      AgentWebSocketServer hostServer = new AgentWebSocketServer(hostServerConfig, handler);
      try {
        hostServer.start();
        return new StartedHostServer(hostServer, port);
      } catch (BindException retry) {
        hostServer.close();
        if (attempt == 4) {
          throw retry;
        }
      }
    }
    throw new IllegalStateException("Failed to start host server");
  }

  private static void disconnectQuietly(AgentClient agentClient) {
    try {
      agentClient.disconnect();
    } catch (RuntimeException ignored) {
      // Ignore secondary close errors after test failure.
    }
  }

  private static void closeQuietly(AgentDispatcher dispatcher) {
    try {
      dispatcher.close();
    } catch (RuntimeException ignored) {
      // Ignore secondary dispatcher close errors after test failure.
    }
  }

  private static void sendClientText(WebSocket socket, String payload) throws Exception {
    socket.sendText(payload, true).get(5, TimeUnit.SECONDS);
  }

  private static void assertReadyNotification(String rawJson, String expectedSessionId) {
    assertNotNull(rawJson);
    Map<String, Object> ready = JsonUtil.parseObject(rawJson);
    assertEquals("2.0", ready.get("jsonrpc"));
    assertEquals("ghidra.ready", ready.get("method"));
    @SuppressWarnings("unchecked")
    Map<String, Object> params = (Map<String, Object>) ready.get("params");
    assertEquals(expectedSessionId, params.get("session_id"));
    assertEquals("test.bin", params.get("program_name"));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> assertMethodError(
      String rawJson, String expectedId, String expectedBridgeCode) {
    assertNotNull(rawJson);
    Map<String, Object> envelope = JsonUtil.parseObject(rawJson);
    assertEquals("2.0", envelope.get("jsonrpc"));
    assertEquals(expectedId, envelope.get("id"));
    Map<String, Object> error = (Map<String, Object>) envelope.get("error");
    assertNotNull(error);
    assertEquals(-32000, error.get("code"));
    Map<String, Object> data = (Map<String, Object>) error.get("data");
    assertNotNull(data);
    assertEquals(expectedBridgeCode, data.get("code"));
    return data;
  }

  @SuppressWarnings("unchecked")
  private static void assertProtocolError(String rawJson, int expectedRpcCode) {
    assertNotNull(rawJson);
    Map<String, Object> envelope = JsonUtil.parseObject(rawJson);
    assertEquals("2.0", envelope.get("jsonrpc"));
    assertTrue(envelope.containsKey("id"));
    assertNull(envelope.get("id"));
    Map<String, Object> error = (Map<String, Object>) envelope.get("error");
    assertNotNull(error);
    assertEquals(expectedRpcCode, error.get("code"));
    Map<String, Object> data = (Map<String, Object>) error.get("data");
    assertNotNull(data);
    assertEquals(400, data.get("status"));
  }

  @SuppressWarnings("unchecked")
  private static void assertSessionFollowup(String rawJson, String expectedSessionId) {
    assertNotNull(rawJson);
    Map<String, Object> envelope = JsonUtil.parseObject(rawJson);
    assertEquals("2.0", envelope.get("jsonrpc"));
    assertEquals("followup-1", envelope.get("id"));
    Map<String, Object> result = (Map<String, Object>) envelope.get("result");
    assertNotNull(result);
    assertEquals(expectedSessionId, result.get("id"));
    assertEquals("active", result.get("status"));
    assertEquals("test.bin", result.get("program_name"));
  }

  private static final class QueueWebSocketListener implements WebSocket.Listener {
    private final BlockingQueue<String> messages;
    private final AtomicBoolean closed;
    private final CountDownLatch closeLatch;
    private final StringBuilder partial = new StringBuilder();

    private QueueWebSocketListener(
        BlockingQueue<String> messages, AtomicBoolean closed, CountDownLatch closeLatch) {
      this.messages = messages;
      this.closed = closed;
      this.closeLatch = closeLatch;
    }

    @Override
    public void onOpen(WebSocket webSocket) {
      webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
      partial.append(data);
      if (last) {
        messages.offer(partial.toString());
        partial.setLength(0);
      }
      webSocket.request(1);
      return null;
    }

    @Override
    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
      closed.set(true);
      closeLatch.countDown();
      return null;
    }

    @Override
    public void onError(WebSocket webSocket, Throwable error) {
      closed.set(true);
      closeLatch.countDown();
    }
  }

  private static final class FakeWebSocket implements WebSocket {
    private final CompletableFuture<WebSocket> customSendResult;
    private final AtomicInteger abortCalls = new AtomicInteger();
    private final AtomicInteger requestCalls = new AtomicInteger();
    private final List<String> sentTexts = Collections.synchronizedList(new ArrayList<>());

    private FakeWebSocket(CompletableFuture<WebSocket> customSendResult) {
      this.customSendResult = customSendResult;
    }

    @Override
    public CompletableFuture<WebSocket> sendText(CharSequence data, boolean last) {
      sentTexts.add(data.toString());
      return customSendResult != null ? customSendResult : CompletableFuture.completedFuture(this);
    }

    @Override
    public CompletableFuture<WebSocket> sendBinary(ByteBuffer data, boolean last) {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public CompletableFuture<WebSocket> sendPing(ByteBuffer message) {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public CompletableFuture<WebSocket> sendPong(ByteBuffer message) {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public CompletableFuture<WebSocket> sendClose(int statusCode, String reason) {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public void request(long n) {
      requestCalls.addAndGet((int) n);
    }

    @Override
    public String getSubprotocol() {
      return "";
    }

    @Override
    public boolean isOutputClosed() {
      return abortCalls.get() > 0;
    }

    @Override
    public boolean isInputClosed() {
      return abortCalls.get() > 0;
    }

    @Override
    public void abort() {
      abortCalls.incrementAndGet();
    }
  }
}
