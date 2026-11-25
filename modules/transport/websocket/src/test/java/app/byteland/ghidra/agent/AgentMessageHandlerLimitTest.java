package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentResource;
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
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AgentMessageHandlerLimitTest {
  private static final String HEX_64K = "cd".repeat(65_536);

  @Test
  void convertsBatchAndResponseSizeViolationsIntoBoundedJsonRpcErrorsWithoutDisconnecting() {
    AtomicInteger memoryReads = new AtomicInteger();
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              memoryReads.incrementAndGet();
              return new MemoryResource(
                  "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, HEX_64K, 65_536));
            });

    String oversizedCommentText = "w".repeat(AgentMessageHandler.MAX_MESSAGE_BYTES + 1_024);
    CommentService oversizedComments =
        proxy(
            CommentService.class,
            (method, args) ->
                Page.of(
                    List.of(
                        new CommentResource(
                            "ram:00100000", CommentResource.Type.EOL, oversizedCommentText)),
                    2,
                    null));

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
            } catch (RuntimeException runtimeError) {
              throw runtimeError;
            } catch (Exception checked) {
              throw new RuntimeException(checked);
            }
          }
        };

    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            oversizedComments,
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
            "ws-test-program");

    AgentConfig config =
        new AgentConfig(null, "127.0.0.1", 18765, "/ws/agent", null, "ws-test-session", null);
    AtomicBoolean disconnected = new AtomicBoolean();
    List<String> sentMessages = new ArrayList<>();

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, config)) {
      AgentMessageHandler handler =
          new AgentMessageHandler(config, dispatcher, () -> disconnected.set(true));
      AgentClientChannels.MessageChannel channel =
          new AgentClientChannels.MessageChannel() {
            @Override
            public void sendText(String message) {
              sentMessages.add(message);
            }

            @Override
            public void close() {
              disconnected.set(true);
            }

            @Override
            public void close(int code, String reason) {
              disconnected.set(true);
            }
          };

      List<Map<String, Object>> batchItems = new ArrayList<>();
      for (int i = 0; i < 100; i++) {
        batchItems.add(
            Map.of(
                "id",
                "m-" + i,
                "method",
                "memory.read",
                "arguments",
                Map.of(
                    "selector",
                    Map.of("address", "ram:00100000"),
                    "length",
                    65_536,
                    "encoding",
                    "hex")));
      }
      String batchRequest =
          JsonUtil.toJson(
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  "batch-1",
                  "method",
                  "batch.execute",
                  "params",
                  Map.of("items", batchItems)));
      handler.handleMessage(channel, batchRequest);

      assertEquals(1, sentMessages.size());
      assertEquals(64, memoryReads.get());
      assertFalse(disconnected.get());
      assertRpcResponseTooLarge(sentMessages.get(0), "batch-1");

      // Direct oversized response exceeding 16 MiB WebSocket frame cap is also caught cleanly.
      String commentRequest =
          JsonUtil.toJson(
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  "comment-1",
                  "method",
                  "comment.get",
                  "params",
                  Map.of("selector", Map.of("address", "ram:00100000", "type", "eol"))));
      handler.handleMessage(channel, commentRequest);

      assertEquals(2, sentMessages.size());
      assertFalse(disconnected.get());
      assertRpcResponseTooLarge(sentMessages.get(1), "comment-1");

      // Oversized error details and unserializable error details both return bounded JSON-RPC errors.
      MemoryService failingDetailsMemory =
          proxy(
              MemoryService.class,
              (method, args) -> {
                if (memoryReads.incrementAndGet() == 65) {
                  throw new app.byteland.ghidra.api.ApiException(
                      400, "bad_input", oversizedCommentText, "/selector");
                }
                throw new app.byteland.ghidra.api.ApiException(
                    400,
                    new app.byteland.ghidra.api.BridgeError(
                        400,
                        "bad_details",
                        "bad",
                        "/selector",
                        Map.of("nested", Map.of(42, "bad-key"))));
              });
      BridgeServices errorServices =
          new BridgeServices(
              unused(ProgramService.class),
              unused(AddressService.class),
              oversizedComments,
              unused(ReferenceService.class),
              failingDetailsMemory,
              unused(ListingService.class),
              unused(FunctionService.class),
              unused(GlobalVariableService.class),
              analysis,
              unused(DecompilationService.class),
              unused(SymbolService.class),
              unused(DataTypeService.class),
              transactions,
              "ws-test-program");
      try (AgentDispatcher errorDispatcher = new AgentDispatcher(errorServices, config)) {
        AgentMessageHandler errorHandler =
            new AgentMessageHandler(config, errorDispatcher, () -> disconnected.set(true));
        String readReq1 =
            JsonUtil.toJson(
                Map.of(
                    "jsonrpc",
                    "2.0",
                    "id",
                    "err-oversized",
                    "method",
                    "memory.read",
                    "params",
                    Map.of(
                        "selector",
                        Map.of("address", "ram:00100000"),
                        "length",
                        16,
                        "encoding",
                        "hex")));
        errorHandler.handleMessage(channel, readReq1);
        assertRpcResponseTooLarge(sentMessages.get(2), "err-oversized");

        String readReq2 =
            JsonUtil.toJson(
                Map.of(
                    "jsonrpc",
                    "2.0",
                    "id",
                    "err-unserializable",
                    "method",
                    "memory.read",
                    "params",
                    Map.of(
                        "selector",
                        Map.of("address", "ram:00100000"),
                        "length",
                        16,
                        "encoding",
                        "hex")));
        errorHandler.handleMessage(channel, readReq2);
        @SuppressWarnings("unchecked")
        Map<String, Object> fallbackEnvelope =
            (Map<String, Object>) JsonUtil.parse(sentMessages.get(3));
        assertEquals("err-unserializable", fallbackEnvelope.get("id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> fallbackError = (Map<String, Object>) fallbackEnvelope.get("error");
        assertEquals(-32000, fallbackError.get("code"));
        @SuppressWarnings("unchecked")
        Map<String, Object> fallbackData = (Map<String, Object>) fallbackError.get("data");
        assertEquals(500, fallbackData.get("status"));
        assertEquals("internal_error", fallbackData.get("code"));
        assertFalse(disconnected.get());
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static void assertRpcResponseTooLarge(String rawJson, String expectedId) {
    Map<String, Object> envelope = (Map<String, Object>) JsonUtil.parse(rawJson);
    assertEquals(expectedId, envelope.get("id"));
    Map<String, Object> rpcError = (Map<String, Object>) envelope.get("error");
    assertNotNull(rpcError);
    assertEquals(-32000, rpcError.get("code"));
    Map<String, Object> data = (Map<String, Object>) rpcError.get("data");
    assertEquals(413, data.get("status"));
    assertEquals("response_too_large", data.get("code"));
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) return null;
          throw new AssertionError("Unexpected call: " + type.getSimpleName() + "." + method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> type.getSimpleName() + "Proxy";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(method.getName(), args);
            }));
  }
}
