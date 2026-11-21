package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
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
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(30)
class AgentClientWebSocketListenerTest {
  private static final int EXACT_LIMIT_BYTES = (int) WebSocketFrames.MAX_FRAME_PAYLOAD_BYTES;

  @Test
  @DisplayName("Reassembles multi-chunk JSON-RPC text messages under 16 MiB")
  void reassemblesMultiChunkMessagesUnderLimit() {
    AtomicInteger demangleCalls = new AtomicInteger();
    TestHarness harness = newHarness(demangleCalls);
    FakeWebSocket webSocket = new FakeWebSocket();

    String fullMessage =
        "{\"jsonrpc\":\"2.0\",\"id\":\"chunked-1\",\"method\":\"symbol.demangle\",\"params\":{}}";
    listenerSendInChunks(harness.listener(), webSocket, fullMessage, 11);

    assertEquals(1, demangleCalls.get());
    assertEquals(1, harness.sentMessages().size());
    Map<?, ?> reply = (Map<?, ?>) JsonUtil.parse(harness.sentMessages().getFirst());
    assertEquals("chunked-1", reply.get("id"));
    assertNotNull(reply.get("result"));
    assertEquals(0, webSocket.closeCalls());
    assertEquals(1L, harness.disconnectLatch().getCount());
    assertNotNull(harness.channelRef().get());
    assertEquals(7L, webSocket.requestedCount());
  }

  @Test
  @DisplayName("Accepts exact 16 MiB single-chunk and multi-chunk messages and trims buffer capacity")
  void acceptsExact16MiBBoundaryAndTrimsCapacity() {
    AtomicInteger demangleCalls = new AtomicInteger();
    TestHarness harness = newHarness(demangleCalls);
    FakeWebSocket webSocket = new FakeWebSocket();

    String prefix =
        "{\"jsonrpc\":\"2.0\",\"id\":\"exact-16mib\",\"method\":\"symbol.demangle\",\"params\":{";
    String suffix = "}}";
    int paddingBytes =
        EXACT_LIMIT_BYTES
            - prefix.getBytes(StandardCharsets.UTF_8).length
            - suffix.getBytes(StandardCharsets.UTF_8).length;
    String padding = " ".repeat(paddingBytes);

    // Multi-chunk exact 16 MiB message
    int half = padding.length() / 2;
    harness.listener().onText(webSocket, prefix, false);
    harness.listener().onText(webSocket, padding.substring(0, half), false);
    harness.listener().onText(webSocket, padding.substring(half), false);
    harness.listener().onText(webSocket, suffix, true);

    assertEquals(1, demangleCalls.get());
    assertEquals(1, harness.sentMessages().size());
    assertTrue(
        harness.listener().pendingBufferCapacity() <= 64 * 1024,
        "Expected StringBuilder capacity to be trimmed after 16 MiB message");
    assertEquals(0, webSocket.closeCalls());

    // Single-chunk exact 16 MiB message followed by a normal message on the same listener
    String exactSingle = prefix + padding + suffix;
    assertEquals(EXACT_LIMIT_BYTES, exactSingle.getBytes(StandardCharsets.UTF_8).length);
    harness.listener().onText(webSocket, exactSingle, true);
    assertEquals(2, demangleCalls.get());

    harness
        .listener()
        .onText(
            webSocket,
            "{\"jsonrpc\":\"2.0\",\"id\":\"after-trim\",\"method\":\"session.get\",\"params\":{}}",
            true);
    assertEquals(3, harness.sentMessages().size());
    Map<?, ?> finalReply = (Map<?, ?>) JsonUtil.parse(harness.sentMessages().getLast());
    assertEquals("after-trim", finalReply.get("id"));
  }

  @Test
  @DisplayName("Rejects oversized message on non-final chunk with close status 1009")
  void rejectsOversizedMessageOnIntermediateChunk() throws InterruptedException {
    AtomicInteger demangleCalls = new AtomicInteger();
    TestHarness harness = newHarness(demangleCalls);
    FakeWebSocket webSocket = new FakeWebSocket();

    String chunk = "a".repeat(4 * 1024 * 1024); // 4 MiB
    harness.listener().onText(webSocket, chunk, false);
    harness.listener().onText(webSocket, chunk, false);
    harness.listener().onText(webSocket, chunk, false);
    harness.listener().onText(webSocket, chunk, false); // 16 MiB exact so far
    assertEquals(4L, webSocket.requestedCount());
    assertEquals(0, webSocket.closeCalls());

    // 16 MiB + 1 byte on last == false
    harness.listener().onText(webSocket, "x", false);

    assertEquals(4L, webSocket.requestedCount(), "Must not request another frame on overflow");
    assertEquals(1, webSocket.closeCalls());
    assertEquals(AgentClientWebSocketListener.MESSAGE_TOO_BIG_CLOSE_CODE, webSocket.lastCloseCode());
    assertTrue(harness.disconnectLatch().await(1, TimeUnit.SECONDS));
    assertNull(harness.channelRef().get());
    assertTrue(harness.listener().pendingBufferCapacity() <= 64 * 1024);
    assertEquals(0, demangleCalls.get());
    assertTrue(harness.sentMessages().isEmpty());

    // Stray trailing callback after close must be ignored
    harness
        .listener()
        .onText(
            webSocket,
            "{\"jsonrpc\":\"2.0\",\"id\":\"after-close\",\"method\":\"symbol.demangle\",\"params\":{}}",
            true);
    assertEquals(0, demangleCalls.get());
    assertEquals(4L, webSocket.requestedCount());
  }

  @Test
  @DisplayName("Rejects oversized message on final chunk with close status 1009")
  void rejectsOversizedMessageOnFinalChunk() throws InterruptedException {
    AtomicInteger demangleCalls = new AtomicInteger();
    TestHarness harness = newHarness(demangleCalls);
    FakeWebSocket webSocket = new FakeWebSocket();

    String almostLimit = "a".repeat(EXACT_LIMIT_BYTES);
    harness.listener().onText(webSocket, almostLimit, false);
    assertEquals(1L, webSocket.requestedCount());
    assertEquals(0, webSocket.closeCalls());

    // Final chunk pushes total to 16 MiB + 1 byte
    harness.listener().onText(webSocket, "b", true);

    assertEquals(1L, webSocket.requestedCount());
    assertEquals(1, webSocket.closeCalls());
    assertEquals(AgentClientWebSocketListener.MESSAGE_TOO_BIG_CLOSE_CODE, webSocket.lastCloseCode());
    assertTrue(harness.disconnectLatch().await(1, TimeUnit.SECONDS));
    assertNull(harness.channelRef().get());
    assertEquals(0, demangleCalls.get());
    assertTrue(harness.sentMessages().isEmpty());
  }

  @Test
  @DisplayName("Counts multi-byte UTF-8 sequences and split surrogate pairs by UTF-8 bytes")
  void countsMultiByteUtf8AndSplitSurrogatePairsAccurately() throws InterruptedException {
    // 1. Exact 16 MiB with multi-byte chars (2-byte é, 3-byte €, and 4-byte 😀 split across chunks)
    AtomicInteger acceptedCalls = new AtomicInteger();
    TestHarness exactHarness = newHarness(acceptedCalls);
    FakeWebSocket exactSocket = new FakeWebSocket();

    String prefix = "{\"jsonrpc\":\"2.0\",\"id\":\"utf8-";
    String middle = "é€"; // 2 + 3 = 5 UTF-8 bytes
    String emoji = "\uD83D\uDE00"; // 4 UTF-8 bytes (2 UTF-16 chars)
    String suffix = "\",\"method\":\"symbol.demangle\",\"params\":{}}";

    int fixedUtf8 =
        prefix.getBytes(StandardCharsets.UTF_8).length
            + middle.getBytes(StandardCharsets.UTF_8).length
            + emoji.getBytes(StandardCharsets.UTF_8).length
            + suffix.getBytes(StandardCharsets.UTF_8).length;
    int remaining = EXACT_LIMIT_BYTES - fixedUtf8;
    int emojiRepeats = remaining / 4;
    int asciiRemainder = remaining % 4;
    String bulkEmojis = emoji.repeat(emojiRepeats) + "x".repeat(asciiRemainder);

    // Split the first emoji's high and low surrogates across two onText calls
    exactHarness.listener().onText(exactSocket, prefix + middle + emoji.substring(0, 1), false);
    exactHarness.listener().onText(exactSocket, emoji.substring(1) + bulkEmojis, false);
    exactHarness.listener().onText(exactSocket, suffix, true);

    assertEquals(1, acceptedCalls.get());
    assertEquals(0, exactSocket.closeCalls());

    // 2. Over 16 MiB in UTF-8 bytes while CharSequence.length() is < 6M chars (3-byte '€')
    AtomicInteger rejectedCalls = new AtomicInteger();
    TestHarness overHarness = newHarness(rejectedCalls);
    FakeWebSocket overSocket = new FakeWebSocket();

    int threeByteCount = (EXACT_LIMIT_BYTES / 3) + 1; // 5,592,406 chars = 16,777,218 UTF-8 bytes
    String threeBytePayload = "€".repeat(threeByteCount);
    assertTrue(threeBytePayload.length() < EXACT_LIMIT_BYTES);
    assertTrue(threeBytePayload.getBytes(StandardCharsets.UTF_8).length > EXACT_LIMIT_BYTES);

    overHarness.listener().onText(overSocket, threeBytePayload, true);

    assertEquals(1, overSocket.closeCalls());
    assertEquals(AgentClientWebSocketListener.MESSAGE_TOO_BIG_CLOSE_CODE, overSocket.lastCloseCode());
    assertTrue(overHarness.disconnectLatch().await(1, TimeUnit.SECONDS));
    assertEquals(0, rejectedCalls.get());
  }

  @Test
  @DisplayName("Aborts WebSocket when sendClose throws synchronously or fails asynchronously")
  void abortsWebSocketWhenSendCloseFails() throws InterruptedException {
    // Synchronous throw from sendClose
    TestHarness syncHarness = newHarness(new AtomicInteger());
    FakeWebSocket throwingSocket =
        new FakeWebSocket(
            (code, reason) -> {
              throw new IllegalStateException("closed already");
            });

    syncHarness.listener().onText(throwingSocket, "a".repeat(EXACT_LIMIT_BYTES + 1), true);
    assertEquals(1, throwingSocket.closeCalls());
    assertTrue(throwingSocket.abortCalls() >= 1);
    assertTrue(syncHarness.disconnectLatch().await(1, TimeUnit.SECONDS));

    // Failed CompletableFuture from sendClose
    TestHarness asyncHarness = newHarness(new AtomicInteger());
    FakeWebSocket failedFutureSocket =
        new FakeWebSocket(
            (code, reason) -> CompletableFuture.failedFuture(new IOException("broken pipe")));

    asyncHarness.listener().onText(failedFutureSocket, "a".repeat(EXACT_LIMIT_BYTES + 1), true);
    assertEquals(1, failedFutureSocket.closeCalls());
    assertTrue(failedFutureSocket.abortCalls() >= 1);
    assertTrue(asyncHarness.disconnectLatch().await(1, TimeUnit.SECONDS));
  }

  @Test
  @DisplayName("Closes with status 1003 and disconnects when receiving a binary frame")
  void closesWith1003OnBinaryFrame() throws InterruptedException {
    AtomicInteger demangleCalls = new AtomicInteger();
    TestHarness harness = newHarness(demangleCalls);
    FakeWebSocket webSocket = new FakeWebSocket();

    harness.listener().onText(webSocket, "{\"partial\":", false);
    assertEquals(1L, webSocket.requestedCount());

    harness.listener().onBinary(webSocket, ByteBuffer.wrap(new byte[] {1, 2, 3}), true);

    assertEquals(1L, webSocket.requestedCount(), "Must not request more frames after binary close");
    assertEquals(1, webSocket.closeCalls());
    assertEquals(
        AgentClientWebSocketListener.UNSUPPORTED_DATA_CLOSE_CODE, webSocket.lastCloseCode());
    assertTrue(harness.disconnectLatch().await(1, TimeUnit.SECONDS));
    assertNull(harness.channelRef().get());
    assertEquals(0, demangleCalls.get());
  }

  @Test
  @DisplayName("Loopback peer: closes with 1009 or EOF before dispatching fragmented >16 MiB stream")
  void loopbackClosesBeforeDispatchingOversizedFragmentedStream() throws Exception {
    AtomicInteger demangleCalls = new AtomicInteger();
    int fragmentSize = 60 * 1024;
    int fragmentCount = 292; // 17,940,480 bytes (> 16 MiB cap)

    byte[] firstFragmentWithMarkerId =
        paddedPrefix(
            "{\"jsonrpc\":\"2.0\",\"id\":\"marker-over-16mib\",\"method\":\"symbol.demangle\",\"params\":{",
            fragmentSize);
    byte[] middleFragment = filledBytes(fragmentSize, (byte) ' ');
    byte[] lastFragment = paddedSuffix("}}", fragmentSize);

    try (ServerSocket serverSocket =
            new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        ExecutorService executor = Executors.newCachedThreadPool()) {
      serverSocket.setSoTimeout(10_000);
      String wsUrl =
          "ws://"
              + serverSocket.getInetAddress().getHostAddress()
              + ":"
              + serverSocket.getLocalPort()
              + "/ws/agent";
      AgentConfig config =
          new AgentConfig(wsUrl, null, null, null, null, "loopback-oversized", null);
      try (AgentDispatcher dispatcher = new AgentDispatcher(stubServices(demangleCalls), config)) {
        AgentClient client =
            new AgentClient(
                config, dispatcher, new AgentClient.LifecycleListener() {}, Duration.ofSeconds(5));

        Future<Void> connectFuture =
            executor.submit(
                () -> {
                  client.connect();
                  return null;
                });

        try (Socket peerSocket = serverSocket.accept()) {
          peerSocket.setTcpNoDelay(true);
          peerSocket.setSoTimeout(10_000);
          InputStream in = peerSocket.getInputStream();
          OutputStream out = peerSocket.getOutputStream();

          WebSocketHandshake.HandshakeRequest handshake = WebSocketHandshake.readHandshake(in);
          WebSocketHandshake.writeHandshakeResponse(out, handshake.acceptKey());

          WebSocketFrames.Frame readyFrame = WebSocketFrames.readFrame(in);
          assertEquals(WebSocketFrames.TEXT_OPCODE, readyFrame.opcode());
          String readyText = new String(readyFrame.payloadView(), StandardCharsets.UTF_8);
          assertTrue(readyText.contains("ghidra.ready"));

          Future<PeerReadOutcome> readFuture = executor.submit(() -> readUntilClosed(in));

          try {
            writeServerFrame(out, false, 0x1, firstFragmentWithMarkerId);
            for (int i = 1; i < fragmentCount - 1; i++) {
              writeServerFrame(out, false, 0x0, middleFragment);
            }
            writeServerFrame(out, true, 0x0, lastFragment);
          } catch (IOException ignoredPeerCloseDuringWrite) {
            // Expected when AgentClient aborts/closes mid-stream once 16 MiB is exceeded.
          }

          PeerReadOutcome outcome = readFuture.get(10, TimeUnit.SECONDS);
          for (String text : outcome.textMessages()) {
            assertFalse(
                text.contains("marker-over-16mib"),
                "Unexpected JSON-RPC reply for oversized message: " + text);
          }
          assertTrue(
              outcome.observedCloseOrEof(),
              "Expected close frame (1009) or EOF from AgentClient");
          if (outcome.closeStatus() != null) {
            assertEquals(
                AgentClientWebSocketListener.MESSAGE_TOO_BIG_CLOSE_CODE, outcome.closeStatus());
          }
        }

        connectFuture.get(10, TimeUnit.SECONDS);
        assertEquals(0, demangleCalls.get(), "Oversized message must never be dispatched");
      }
    }
  }

  @Test
  @DisplayName("Loopback peer: dispatches multi-fragment message under 16 MiB and closes 1003 on binary")
  void loopbackDispatchesFragmentedMessageUnderCapAndRejectsBinary() throws Exception {
    AtomicInteger demangleCalls = new AtomicInteger();

    try (ServerSocket serverSocket =
            new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        ExecutorService executor = Executors.newCachedThreadPool()) {
      serverSocket.setSoTimeout(10_000);
      String wsUrl =
          "ws://"
              + serverSocket.getInetAddress().getHostAddress()
              + ":"
              + serverSocket.getLocalPort()
              + "/ws/agent";
      AgentConfig config =
          new AgentConfig(wsUrl, null, null, null, null, "loopback-valid", null);
      try (AgentDispatcher dispatcher = new AgentDispatcher(stubServices(demangleCalls), config)) {
        AgentClient client =
            new AgentClient(
                config, dispatcher, new AgentClient.LifecycleListener() {}, Duration.ofSeconds(5));

        Future<Void> connectFuture =
            executor.submit(
                () -> {
                  client.connect();
                  return null;
                });

        try (Socket peerSocket = serverSocket.accept()) {
          peerSocket.setTcpNoDelay(true);
          peerSocket.setSoTimeout(10_000);
          InputStream in = peerSocket.getInputStream();
          OutputStream out = peerSocket.getOutputStream();

          WebSocketHandshake.HandshakeRequest handshake = WebSocketHandshake.readHandshake(in);
          WebSocketHandshake.writeHandshakeResponse(out, handshake.acceptKey());

          WebSocketFrames.Frame readyFrame = WebSocketFrames.readFrame(in);
          assertEquals(WebSocketFrames.TEXT_OPCODE, readyFrame.opcode());

          // Send a valid 180 KiB JSON-RPC request across 3 WebSocket fragments
          byte[] part1 =
              paddedPrefix(
                  "{\"jsonrpc\":\"2.0\",\"id\":\"under-16mib-ok\",\"method\":\"symbol.demangle\",\"params\":{",
                  60 * 1024);
          byte[] part2 = filledBytes(60 * 1024, (byte) ' ');
          byte[] part3 = paddedSuffix("}}", 60 * 1024);

          writeServerFrame(out, false, 0x1, part1);
          writeServerFrame(out, false, 0x0, part2);
          writeServerFrame(out, true, 0x0, part3);

          WebSocketFrames.Frame responseFrame = readNextNonPingFrame(in);
          assertEquals(WebSocketFrames.TEXT_OPCODE, responseFrame.opcode());
          Map<?, ?> response =
              (Map<?, ?>)
                  JsonUtil.parse(new String(responseFrame.payloadView(), StandardCharsets.UTF_8));
          assertEquals("under-16mib-ok", response.get("id"));
          assertEquals(1, demangleCalls.get());

          // Send a single 512 KiB FIN=1 frame that JDK splits across multiple onText calls
          String singlePrefix =
              "{\"jsonrpc\":\"2.0\",\"id\":\"large-fin1-ok\",\"method\":\"symbol.demangle\",\"params\":{";
          byte[] singleLargeFrame = paddedPrefix(singlePrefix, 512 * 1024);
          singleLargeFrame[singleLargeFrame.length - 2] = '}';
          singleLargeFrame[singleLargeFrame.length - 1] = '}';
          writeServerFrame(out, true, 0x1, singleLargeFrame);

          WebSocketFrames.Frame largeResponseFrame = readNextNonPingFrame(in);
          assertEquals(WebSocketFrames.TEXT_OPCODE, largeResponseFrame.opcode());
          Map<?, ?> largeResponse =
              (Map<?, ?>)
                  JsonUtil.parse(
                      new String(largeResponseFrame.payloadView(), StandardCharsets.UTF_8));
          assertEquals("large-fin1-ok", largeResponse.get("id"));
          assertEquals(2, demangleCalls.get());

          // Now send an unsupported binary frame (opcode 0x2) and expect close 1003 or EOF
          writeServerFrame(out, true, 0x2, new byte[] {0x01, 0x02});
          PeerReadOutcome binaryClose = readUntilClosed(in);
          assertTrue(binaryClose.observedCloseOrEof());
          if (binaryClose.closeStatus() != null) {
            assertEquals(
                AgentClientWebSocketListener.UNSUPPORTED_DATA_CLOSE_CODE,
                binaryClose.closeStatus());
          }
        }

        connectFuture.get(10, TimeUnit.SECONDS);
      }
    }
  }

  private static void listenerSendInChunks(
      AgentClientWebSocketListener listener,
      WebSocket webSocket,
      String message,
      int chunkSize) {
    for (int offset = 0; offset < message.length(); offset += chunkSize) {
      int end = Math.min(offset + chunkSize, message.length());
      boolean last = end == message.length();
      listener.onText(webSocket, message.substring(offset, end), last);
    }
  }

  private static byte[] paddedPrefix(String prefix, int totalBytes) {
    byte[] prefixBytes = prefix.getBytes(StandardCharsets.UTF_8);
    byte[] result = filledBytes(totalBytes, (byte) ' ');
    System.arraycopy(prefixBytes, 0, result, 0, prefixBytes.length);
    return result;
  }

  private static byte[] paddedSuffix(String suffix, int totalBytes) {
    byte[] suffixBytes = suffix.getBytes(StandardCharsets.UTF_8);
    byte[] result = filledBytes(totalBytes, (byte) ' ');
    System.arraycopy(
        suffixBytes, 0, result, totalBytes - suffixBytes.length, suffixBytes.length);
    return result;
  }

  private static byte[] filledBytes(int length, byte value) {
    byte[] data = new byte[length];
    Arrays.fill(data, value);
    return data;
  }

  private static void writeServerFrame(
      OutputStream output, boolean fin, int opcode, byte[] payload) throws IOException {
    output.write((fin ? 0x80 : 0x00) | (opcode & 0x0F));
    long length = payload.length;
    if (length <= 125) {
      output.write((int) length);
    } else if (length <= 0xFFFF) {
      output.write(126);
      output.write((int) ((length >>> 8) & 0xFF));
      output.write((int) (length & 0xFF));
    } else {
      output.write(127);
      for (int shift = 56; shift >= 0; shift -= 8) {
        output.write((int) ((length >>> shift) & 0xFF));
      }
    }
    output.write(payload);
    output.flush();
  }

  private static WebSocketFrames.Frame readNextNonPingFrame(InputStream in) throws IOException {
    while (true) {
      WebSocketFrames.Frame frame = WebSocketFrames.readFrame(in);
      if (frame.opcode() != WebSocketFrames.PING_OPCODE
          && frame.opcode() != WebSocketFrames.PONG_OPCODE) {
        return frame;
      }
    }
  }

  private static PeerReadOutcome readUntilClosed(InputStream in) throws IOException {
    List<String> textMessages = new ArrayList<>();
    while (true) {
      try {
        WebSocketFrames.Frame frame = WebSocketFrames.readFrame(in);
        if (frame.opcode() == WebSocketFrames.TEXT_OPCODE) {
          textMessages.add(new String(frame.payloadView(), StandardCharsets.UTF_8));
        } else if (frame.opcode() == WebSocketFrames.CLOSE_OPCODE) {
          return new PeerReadOutcome(
              textMessages, WebSocketFrames.closeStatus(frame.payloadView()), true);
        }
      } catch (EOFException | SocketException closed) {
        return new PeerReadOutcome(textMessages, null, true);
      }
    }
  }

  private record PeerReadOutcome(
      List<String> textMessages, Integer closeStatus, boolean observedCloseOrEof) {}

  private static TestHarness newHarness(AtomicInteger demangleCalls) {
    AgentConfig config = new AgentConfig("ws://127.0.0.1:9/ws/agent", null, null, null, null, "test", null);
    AgentDispatcher dispatcher = new AgentDispatcher(stubServices(demangleCalls), config);
    List<String> sentMessages = Collections.synchronizedList(new ArrayList<>());
    AgentClientChannels.MessageChannel recordingChannel =
        new AgentClientChannels.MessageChannel() {
          @Override
          public void sendText(String message) {
            sentMessages.add(message);
          }

          @Override
          public void close() {}

          @Override
          public void close(int code, String reason) {}
        };
    AtomicReference<AgentClientChannels.MessageChannel> channelRef =
        new AtomicReference<>(recordingChannel);
    CountDownLatch disconnectLatch = new CountDownLatch(1);
    AgentMessageHandler messageHandler =
        new AgentMessageHandler(config, dispatcher, disconnectLatch::countDown);
    AgentClientWebSocketListener listener =
        new AgentClientWebSocketListener(channelRef, disconnectLatch, messageHandler);
    return new TestHarness(listener, channelRef, disconnectLatch, sentMessages);
  }

  private record TestHarness(
      AgentClientWebSocketListener listener,
      AtomicReference<AgentClientChannels.MessageChannel> channelRef,
      CountDownLatch disconnectLatch,
      List<String> sentMessages) {}

  private static BridgeServices stubServices(AtomicInteger demangleCalls) {
    SymbolService symbols =
        proxy(
            SymbolService.class,
            (method, args) -> {
              if ("demangleSymbols".equals(method)) {
                demangleCalls.incrementAndGet();
                return new SymbolService.DemangleResult(0, 0, List.of());
              }
              throw new AssertionError("Unexpected SymbolService call: " + method);
            });
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) -> {
              if ("close".equals(method)) {
                return null;
              }
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
              if ("close".equals(method)) {
                return null;
              }
              throw new AssertionError("Unexpected DecompilationService call: " + method);
            });
    TransactionRunner transactionRunner =
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
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysis,
        decompilation,
        symbols,
        unused(DataTypeService.class),
        transactionRunner,
        "sample.bin");
  }

  private interface InvocationCallback {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("Unexpected call: " + method);
        });
  }

  private static <T> T proxy(Class<T> type, InvocationCallback callback) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (instance, method, args) -> callback.invoke(method.getName(), args)));
  }

  private static final class FakeWebSocket implements WebSocket {
    private final BiFunction<Integer, String, CompletableFuture<WebSocket>> closeBehavior;
    private final AtomicLong requested = new AtomicLong();
    private final AtomicInteger closeCount = new AtomicInteger();
    private final AtomicInteger abortCount = new AtomicInteger();
    private volatile int closeCode = -1;
    private volatile String closeReason;

    FakeWebSocket() {
      this(null);
    }

    FakeWebSocket(BiFunction<Integer, String, CompletableFuture<WebSocket>> closeBehavior) {
      this.closeBehavior = closeBehavior;
    }

    long requestedCount() {
      return requested.get();
    }

    int closeCalls() {
      return closeCount.get();
    }

    int abortCalls() {
      return abortCount.get();
    }

    int lastCloseCode() {
      return closeCode;
    }

    String lastCloseReason() {
      return closeReason;
    }

    @Override
    public CompletableFuture<WebSocket> sendText(CharSequence data, boolean last) {
      return CompletableFuture.completedFuture(this);
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
      closeCount.incrementAndGet();
      this.closeCode = statusCode;
      this.closeReason = reason;
      if (closeBehavior != null) {
        return closeBehavior.apply(statusCode, reason);
      }
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public void request(long n) {
      requested.addAndGet(n);
    }

    @Override
    public String getSubprotocol() {
      return "";
    }

    @Override
    public boolean isOutputClosed() {
      return closeCount.get() > 0 || abortCount.get() > 0;
    }

    @Override
    public boolean isInputClosed() {
      return abortCount.get() > 0;
    }

    @Override
    public void abort() {
      abortCount.incrementAndGet();
    }
  }
}
