package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
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
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Proxy;
import java.net.http.WebSocket;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentClientWebSocketListenerTest {

  @Test
  @DisplayName("Single-frame messages call data.toString() directly without growing pendingText")
  void singleFrameFastPathUsesDirectToStringWithoutGrowingBuffer() {
    TestHarness harness = new TestHarness();
    String largeId = "req-" + "x".repeat(80 * 1024);
    String json =
        JsonUtil.toJson(Map.of("jsonrpc", "2.0", "id", largeId, "method", "session.get"));
    TrackingCharSequence singleFrame = new TrackingCharSequence(json);

    harness.listener.onText(harness.webSocket, singleFrame, true);

    assertEquals(1, singleFrame.toStringCalls());
    assertEquals(0, singleFrame.charAccessCalls());
    assertEquals(0, harness.listener.pendingBufferLength());
    assertEquals(16, harness.listener.pendingBufferCapacity());
    assertEquals(1L, harness.requestedFrames.get());
    assertEquals(1, harness.sentMessages.size());

    Map<?, ?> response = (Map<?, ?>) JsonUtil.parse(harness.sentMessages.get(0));
    assertEquals(largeId, response.get("id"));
  }

  @Test
  @DisplayName("Multi-chunk UTF-8 fragments reassemble split surrogates and empty final chunks")
  void multiChunkUtf8ReassemblyPreservesMultibyteAndSplitSurrogates() {
    TestHarness harness = new TestHarness();
    String utf8Id = "café-逆向工程-\uD83D\uDE80-\uD83E\uDDE9-Ω";
    String json =
        JsonUtil.toJson(Map.of("jsonrpc", "2.0", "id", utf8Id, "method", "session.get"));

    int highSurrogateIndex = json.indexOf('\uD83D');
    assertTrue(highSurrogateIndex > 0);

    // Split right between the UTF-16 high and low surrogates, include an empty middle chunk,
    // and finish with an empty final chunk.
    String part1 = json.substring(0, highSurrogateIndex + 1);
    String part2 = json.substring(highSurrogateIndex + 1, highSurrogateIndex + 8);
    String part3 = json.substring(highSurrogateIndex + 8);

    harness.listener.onText(harness.webSocket, CharBuffer.wrap(part1), false);
    harness.listener.onText(harness.webSocket, "", false);
    harness.listener.onText(harness.webSocket, CharBuffer.wrap(part2), false);
    harness.listener.onText(harness.webSocket, part3, false);
    assertTrue(harness.listener.pendingBufferLength() > 0);
    assertTrue(harness.sentMessages.isEmpty());

    harness.listener.onText(harness.webSocket, "", true);

    assertEquals(0, harness.listener.pendingBufferLength());
    assertEquals(5L, harness.requestedFrames.get());
    assertEquals(1, harness.sentMessages.size());

    Map<?, ?> response = (Map<?, ?>) JsonUtil.parse(harness.sentMessages.get(0));
    assertEquals(utf8Id, response.get("id"));
  }

  @Test
  @DisplayName("Retains <= 64 KiB buffer capacity and shrinks > 64 KiB capacity before dispatch")
  void retainsModerateCapacityAndShrinksAfterTwoMegabytePayload() {
    AtomicInteger lengthDuringDispatch = new AtomicInteger(-1);
    AtomicInteger capacityDuringDispatch = new AtomicInteger(-1);
    AtomicReference<ByteSequence> capturedPatch = new AtomicReference<>();

    TestHarness harness =
        new TestHarness(
            (listener, startRaw, bytes) -> {
              lengthDuringDispatch.set(listener.pendingBufferLength());
              capacityDuringDispatch.set(listener.pendingBufferCapacity());
              capturedPatch.set(bytes);
            });

    // 1. Send a 24 KiB multi-chunk request (buffer capacity 32,774 <= 64 KiB cap) and verify reuse.
    String moderateId = "m".repeat(24 * 1024);
    String moderateJson =
        JsonUtil.toJson(Map.of("jsonrpc", "2.0", "id", moderateId, "method", "session.get"));
    sendInChunks(harness.listener, harness.webSocket, moderateJson, 8 * 1024);

    assertEquals(0, harness.listener.pendingBufferLength());
    int retainedCapacity = harness.listener.pendingBufferCapacity();
    assertTrue(retainedCapacity >= moderateJson.length());
    assertTrue(retainedCapacity <= AgentClientWebSocketListener.MAX_RETAINED_BUFFER_CAPACITY);
    assertEquals(1, harness.sentMessages.size());

    // 2. Send a 2 MiB hex memory.write payload across 8 KiB chunks (> 64 KiB cap).
    int rawByteLength = 1024 * 1024;
    String twoMiBHex = "ab".repeat(rawByteLength);
    assertEquals(2 * 1024 * 1024, twoMiBHex.length());
    String largeWriteJson =
        JsonUtil.toJson(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                "write-2m",
                "method",
                "memory.write",
                "params",
                Map.of(
                    "selector",
                    Map.of("address", "0x1000"),
                    "patch",
                    Map.of(
                        "bytes",
                        Map.of(
                            "encoding", "hex",
                            "data", twoMiBHex,
                            "length", rawByteLength)))));

    sendInChunks(harness.listener, harness.webSocket, largeWriteJson, 8 * 1024);

    // Oversized buffer must be cleared and shrunk BEFORE handleMessage dispatches the request.
    assertEquals(0, lengthDuringDispatch.get());
    assertEquals(16, capacityDuringDispatch.get());
    assertEquals(0, harness.listener.pendingBufferLength());
    assertEquals(16, harness.listener.pendingBufferCapacity());

    assertEquals(twoMiBHex, capturedPatch.get().data());
    assertEquals(rawByteLength, capturedPatch.get().length());
    assertEquals(2, harness.sentMessages.size());
    Map<?, ?> writeResponse = (Map<?, ?>) JsonUtil.parse(harness.sentMessages.get(1));
    assertEquals("write-2m", writeResponse.get("id"));
    assertEquals(
        Map.of("start", "ram:00001000", "length", rawByteLength), writeResponse.get("result"));

    // 3. Subsequent multi-chunk and single-frame messages continue cleanly.
    String followUpJson =
        JsonUtil.toJson(Map.of("jsonrpc", "2.0", "id", "after-shrink", "method", "session.get"));
    sendInChunks(harness.listener, harness.webSocket, followUpJson, 12);
    assertEquals(3, harness.sentMessages.size());
    Map<?, ?> followUpResponse = (Map<?, ?>) JsonUtil.parse(harness.sentMessages.get(2));
    assertEquals("after-shrink", followUpResponse.get("id"));
  }

  @Test
  @DisplayName("Clears and shrinks buffer and ends session when handleMessage throws RuntimeException")
  void clearsAndShrinksBufferOnHandleMessageFailure() {
    TestHarness harness = new TestHarness();
    harness.failOnSend = true;

    String payload =
        JsonUtil.toJson(
            Map.of("jsonrpc", "2.0", "id", "f".repeat(24 * 1024), "method", "session.get"));
    int split = payload.length() / 2;

    harness.listener.onText(harness.webSocket, payload.substring(0, split), false);
    assertEquals(1L, harness.requestedFrames.get());
    assertTrue(harness.listener.pendingBufferCapacity() > 16);

    harness.listener.onText(harness.webSocket, payload.substring(split), true);

    assertEquals(0, harness.listener.pendingBufferLength());
    assertEquals(16, harness.listener.pendingBufferCapacity());
    assertNull(harness.channelRef.get());
    assertEquals(0L, harness.disconnectLatch.getCount());
    // Must not request another frame after transport send failure.
    assertEquals(1L, harness.requestedFrames.get());
  }

  @Test
  @DisplayName("Clears and shrinks partial fragment buffers on close and error")
  void clearsAndShrinksPartialBuffersOnCloseAndError() {
    TestHarness closeHarness = new TestHarness();
    closeHarness.listener.onText(closeHarness.webSocket, "p".repeat(48 * 1024), false);
    assertEquals(48 * 1024, closeHarness.listener.pendingBufferLength());
    assertTrue(closeHarness.listener.pendingBufferCapacity() >= 48 * 1024);

    closeHarness.listener.onClose(closeHarness.webSocket, WebSocket.NORMAL_CLOSURE, "closed");
    assertEquals(0, closeHarness.listener.pendingBufferLength());
    assertEquals(16, closeHarness.listener.pendingBufferCapacity());
    assertNull(closeHarness.channelRef.get());
    assertEquals(0L, closeHarness.disconnectLatch.getCount());

    TestHarness errorHarness = new TestHarness();
    errorHarness.listener.onText(errorHarness.webSocket, "e".repeat(128 * 1024), false);
    assertEquals(128 * 1024, errorHarness.listener.pendingBufferLength());
    assertTrue(
        errorHarness.listener.pendingBufferCapacity()
            > AgentClientWebSocketListener.MAX_RETAINED_BUFFER_CAPACITY);

    errorHarness.listener.onError(errorHarness.webSocket, new IOException("connection reset"));
    assertEquals(0, errorHarness.listener.pendingBufferLength());
    assertEquals(16, errorHarness.listener.pendingBufferCapacity());
    assertNull(errorHarness.channelRef.get());
    assertEquals(0L, errorHarness.disconnectLatch.getCount());
  }

  @Test
  @DisplayName("Reassembles 2 MiB across 8 KiB chunks with linear O(N) memory allocation")
  void reassemblesLargeFragmentedPayloadsWithLinearAllocationScaling() {
    TestHarness harness = new TestHarness();
    // Null channel isolates AgentClientWebSocketListener reassembly from JSON parser allocations
    // while still executing consumeCompleteMessage(data) on the final fragment.
    harness.channelRef.set(null);

    String chunk = "a".repeat(8 * 1024);
    for (int warmup = 0; warmup < 5; warmup++) {
      sendRepeatedChunks(harness.listener, harness.webSocket, chunk, 32);
    }

    java.lang.management.ThreadMXBean baseBean = ManagementFactory.getThreadMXBean();
    assertTrue(baseBean instanceof com.sun.management.ThreadMXBean);
    com.sun.management.ThreadMXBean threadBean = (com.sun.management.ThreadMXBean) baseBean;
    assertTrue(threadBean.isThreadAllocatedMemorySupported());
    if (!threadBean.isThreadAllocatedMemoryEnabled()) {
      threadBean.setThreadAllocatedMemoryEnabled(true);
    }

    long currentThreadId = Thread.currentThread().threadId();

    long before512KiB = threadBean.getThreadAllocatedBytes(currentThreadId);
    sendRepeatedChunks(harness.listener, harness.webSocket, chunk, 64); // 512 KiB
    long allocated512KiB = threadBean.getThreadAllocatedBytes(currentThreadId) - before512KiB;

    long before2MiB = threadBean.getThreadAllocatedBytes(currentThreadId);
    sendRepeatedChunks(harness.listener, harness.webSocket, chunk, 256); // 2 MiB
    long allocated2MiB = threadBean.getThreadAllocatedBytes(currentThreadId) - before2MiB;

    assertEquals(0, harness.listener.pendingBufferLength());
    assertEquals(16, harness.listener.pendingBufferCapacity());

    // Quadratic String += copied 269,484,032 bytes for 256 x 8 KiB chunks; StringBuilder stays
    // well below 24 MiB and scales ~4x from 512 KiB to 2 MiB instead of ~16x.
    assertTrue(
        allocated2MiB < 24L * 1024 * 1024,
        "Expected linear allocation (< 24 MiB) for 2 MiB payload, got " + allocated2MiB + " bytes");
    double growthRatio = (double) allocated2MiB / Math.max(1L, allocated512KiB);
    assertFalse(
        growthRatio > 6.5,
        "Expected near-linear ~4x allocation growth from 512 KiB to 2 MiB, got "
            + growthRatio
            + "x ("
            + allocated512KiB
            + " -> "
            + allocated2MiB
            + " bytes)");
  }

  private static void sendInChunks(
      AgentClientWebSocketListener listener, WebSocket webSocket, String message, int chunkSize) {
    for (int offset = 0; offset < message.length(); offset += chunkSize) {
      int end = Math.min(offset + chunkSize, message.length());
      boolean last = end == message.length();
      listener.onText(webSocket, message.substring(offset, end), last);
    }
  }

  private static void sendRepeatedChunks(
      AgentClientWebSocketListener listener, WebSocket webSocket, String chunk, int count) {
    for (int i = 0; i < count; i++) {
      listener.onText(webSocket, chunk, i == count - 1);
    }
  }

  @FunctionalInterface
  private interface PatchObserver {
    void onPatch(AgentClientWebSocketListener listener, String startRaw, ByteSequence bytes);
  }

  private static final class TrackingCharSequence implements CharSequence {
    private final String delegate;
    private int toStringCalls;
    private int charAccessCalls;

    private TrackingCharSequence(String delegate) {
      this.delegate = delegate;
    }

    @Override
    public int length() {
      return delegate.length();
    }

    @Override
    public char charAt(int index) {
      charAccessCalls++;
      return delegate.charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
      charAccessCalls++;
      return delegate.subSequence(start, end);
    }

    @Override
    public String toString() {
      toStringCalls++;
      return delegate;
    }

    int toStringCalls() {
      return toStringCalls;
    }

    int charAccessCalls() {
      return charAccessCalls;
    }
  }

  private static final class TestHarness {
    private final List<String> sentMessages = new ArrayList<>();
    private final java.util.concurrent.atomic.AtomicLong requestedFrames =
        new java.util.concurrent.atomic.AtomicLong();
    private final CountDownLatch disconnectLatch = new CountDownLatch(1);
    private final AtomicReference<AgentClientChannels.MessageChannel> channelRef =
        new AtomicReference<>();
    private final WebSocket webSocket;
    private final AgentClientWebSocketListener listener;
    private boolean failOnSend;

    private TestHarness() {
      this((ignoredListener, ignoredStart, ignoredBytes) -> {});
    }

    private TestHarness(PatchObserver patchObserver) {
      AgentConfig config =
          AgentConfig.fromMap(
              Map.of("ws_url", "ws://127.0.0.1:8765/ws/agent", "session_id", "test-session"));
      AtomicReference<AgentClientWebSocketListener> listenerRef = new AtomicReference<>();
      BridgeServices services = buildServices(listenerRef, patchObserver);
      AgentDispatcher dispatcher = new AgentDispatcher(services, config);
      AgentMessageHandler messageHandler = new AgentMessageHandler(config, dispatcher, () -> {});

      AgentClientChannels.MessageChannel channel =
          new AgentClientChannels.MessageChannel() {
            @Override
            public void sendText(String message) {
              if (failOnSend) {
                throw new UncheckedIOException(new IOException("broken pipe"));
              }
              sentMessages.add(message);
            }

            @Override
            public void close() {}

            @Override
            public void close(int code, String reason) {}
          };
      channelRef.set(channel);

      this.webSocket =
          (WebSocket)
              Proxy.newProxyInstance(
                  WebSocket.class.getClassLoader(),
                  new Class<?>[] {WebSocket.class},
                  (proxy, method, args) -> {
                    if ("request".equals(method.getName())) {
                      requestedFrames.addAndGet((Long) args[0]);
                      return null;
                    }
                    if (method.getDeclaringClass() == Object.class) {
                      return switch (method.getName()) {
                        case "toString" -> "TestWebSocket";
                        case "hashCode" -> System.identityHashCode(proxy);
                        case "equals" -> proxy == args[0];
                        default -> null;
                      };
                    }
                    throw new UnsupportedOperationException(method.getName());
                  });
      this.listener = new AgentClientWebSocketListener(channelRef, disconnectLatch, messageHandler);
      listenerRef.set(this.listener);
    }

    private static BridgeServices buildServices(
        AtomicReference<AgentClientWebSocketListener> listenerRef, PatchObserver patchObserver) {
      AddressService addresses =
          rawAddress ->
              new AddressResource("ram:00001000", true, true, null, null, null, null);
      MemoryService memory =
          proxy(
              MemoryService.class,
              (method, args) -> {
                if ("patchMemory".equals(method)) {
                  patchObserver.onPatch(
                      listenerRef.get(), (String) args[0], (ByteSequence) args[1]);
                  return null;
                }
                throw new AssertionError("Unexpected MemoryService call: " + method);
              });
      AnalysisService analysis =
          proxy(
              AnalysisService.class,
              (method, args) ->
                  new AnalysisResource(
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
              } catch (RuntimeException runtime) {
                throw runtime;
              } catch (Exception checked) {
                throw new IllegalStateException(checked);
              }
            }
          };
      return new BridgeServices(
          unused(ProgramService.class),
          addresses,
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
          "test-program");
    }

    private interface MethodInvocationHandler {
      Object invoke(String method, Object[] args);
    }

    private static <T> T unused(Class<T> type) {
      return proxy(
          type,
          (method, args) -> {
            if ("close".equals(method)) {
              return null;
            }
            throw new AssertionError("Unexpected call: " + type.getSimpleName() + "." + method);
          });
    }

    private static <T> T proxy(Class<T> type, MethodInvocationHandler handler) {
      return type.cast(
          Proxy.newProxyInstance(
              type.getClassLoader(),
              new Class<?>[] {type},
              (proxy, method, args) -> {
                if (method.getDeclaringClass() == Object.class) {
                  return switch (method.getName()) {
                    case "toString" -> "TestProxy[" + type.getSimpleName() + "]";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> null;
                  };
                }
                return handler.invoke(method.getName(), args);
              }));
    }
  }
}
