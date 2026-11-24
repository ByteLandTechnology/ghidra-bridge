package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
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
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class McpHttpServerBatchLimitTest {
  private static final long NANOS_PER_MS = 1_000_000L;
  private static final String HEX_64K = "ab".repeat(65_536);

  private static final String SINGLE_SCAN_BATCH_JSON =
      "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ghidra_batch\",\"arguments\":{\"operation\":\"execute\",\"params\":{\"items\":[{\"id\":\"scan-0\",\"method\":\"code_unit.list\",\"arguments\":{\"scan\":{\"range\":{\"start\":\"ram:00100000\",\"end\":\"ram:7fffffff\"},\"timeout_ms\":100},\"page\":{\"limit\":10}}}]}}}}";

  private static final String SINGLE_MEMORY_BATCH_JSON =
      "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"ghidra_batch\",\"arguments\":{\"operation\":\"execute\",\"params\":{\"items\":[{\"id\":\"m-0\",\"method\":\"memory.read\",\"arguments\":{\"selector\":{\"address\":\"ram:00100000\"},\"length\":65536,\"encoding\":\"hex\"}}]}}}}";

  @Test
  void memoryReadBatchesStreamValidResponsesAndBoundOversizedBatchesOverMcpHttp()
      throws Exception {
    AtomicInteger memoryReads = new AtomicInteger();
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("readMemoryRange", method);
              memoryReads.incrementAndGet();
              return new MemoryResource(
                  "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, HEX_64K, 65_536));
            });

    try (TestMcpServer harness =
        startServer(memory, unused(ListingService.class), unused(CommentService.class), System::nanoTime)) {
      HttpResponse<byte[]> singleResponse = harness.postRaw(SINGLE_MEMORY_BATCH_JSON);
      assertEquals(200, singleResponse.statusCode());
      assertEquals(
          singleResponse.body().length,
          Integer.parseInt(singleResponse.headers().firstValue("Content-Length").orElseThrow()));
      Map<String, Object> singleResult = unwrapResult(singleResponse);
      assertEquals(Boolean.FALSE, singleResult.get("isError"));
      assertEquals(1, memoryReads.get());

      // Near-limit 62-item (~8.1 MiB) batch succeeds and streams UTF-8 with exact Content-Length.
      memoryReads.set(0);
      HttpResponse<byte[]> validNearLimit = harness.postRaw(buildMemoryBatchRequestJson(3, 62));
      assertEquals(200, validNearLimit.statusCode());
      assertEquals(
          validNearLimit.body().length,
          Integer.parseInt(validNearLimit.headers().firstValue("Content-Length").orElseThrow()));
      assertEquals(Boolean.FALSE, unwrapResult(validNearLimit).get("isError"));
      assertEquals(62, memoryReads.get());

      // 1,000-item 65,536-byte hex memory.read batch fails with bounded 413 response_too_large.
      memoryReads.set(0);
      String oversizedBatchJson = buildMemoryBatchRequestJson(4, 1_000);
      HttpResponse<byte[]> oversizedResponse = harness.postRaw(oversizedBatchJson);
      assertEquals(200, oversizedResponse.statusCode());
      assertTrue(oversizedResponse.body().length < 4_096);

      Map<String, Object> errorToolResult = unwrapResult(oversizedResponse);
      assertEquals(Boolean.TRUE, errorToolResult.get("isError"));
      @SuppressWarnings("unchecked")
      Map<String, Object> structuredError =
          (Map<String, Object>) errorToolResult.get("structuredContent");
      assertEquals(413, structuredError.get("status"));
      assertEquals("response_too_large", structuredError.get("code"));
      @SuppressWarnings("unchecked")
      Map<String, Object> details = (Map<String, Object>) structuredError.get("details");
      assertEquals("m-63", details.get("failed_item"));
      assertEquals(64, memoryReads.get());
    }
  }

  @Test
  void codeUnitScanBatchesClampTimeoutEnforceDeadlineAndReleaseSequenceLock() throws Exception {
    AtomicLong fakeNanos = new AtomicLong(10_000_000L);
    List<Integer> observedTimeouts = new ArrayList<>();
    CountDownLatch secondScanEntered = new CountDownLatch(1);
    CountDownLatch releaseSecondScan = new CountDownLatch(1);

    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              assertEquals("listCodeUnits", method);
              AddressScanOptions scan = (AddressScanOptions) args[0];
              int callNumber;
              synchronized (observedTimeouts) {
                observedTimeouts.add(scan.timeoutMs());
                callNumber = observedTimeouts.size();
              }
              if (callNumber == 1) {
                fakeNanos.addAndGet(59_960L * NANOS_PER_MS);
              } else if (callNumber == 2) {
                secondScanEntered.countDown();
                try {
                  assertTrue(releaseSecondScan.await(5, TimeUnit.SECONDS));
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                }
                fakeNanos.addAndGet(50L * NANOS_PER_MS);
              }
              CodeUnitResource item =
                  new CodeUnitResource(
                      "ram:00100000",
                      CodeUnitResource.Kind.INSTRUCTION,
                      1,
                      new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                      "NOP",
                      "NOP",
                      List.of(),
                      null,
                      null,
                      null);
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      scan.start(),
                      scan.end(),
                      "ram:00100000",
                      "ram:00100000",
                      false,
                      ScanProgress.StopReason.TIMEOUT,
                      scan.timeoutMs());
              return Page.scanned(List.of(item), 10, "ram:00100000", progress);
            });

    try (TestMcpServer harness =
        startServer(unused(MemoryService.class), listing, unused(CommentService.class), fakeNanos::get)) {
      // Verify exact single-item scan payload from the specification succeeds when within budget.
      fakeNanos.set(10_000_000L);
      HttpResponse<byte[]> singleScan = harness.postRaw(SINGLE_SCAN_BATCH_JSON);
      assertEquals(200, singleScan.statusCode());
      Map<String, Object> singleResult = unwrapResult(singleScan);
      assertEquals(Boolean.FALSE, singleResult.get("isError"));

      // Reset state and run an 8-item scan batch that hits the 60,000 ms deadline after item 2,
      // while a concurrent session.get waits on AgentDispatcher.sequenceLock.
      synchronized (observedTimeouts) {
        observedTimeouts.clear();
      }
      fakeNanos.set(10_000_000L);

      String eightItemScanBatch = buildScanBatchRequestJson(2, 8, 100);
      CompletableFuture<HttpResponse<byte[]>> batchFuture =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  return harness.postRaw(eightItemScanBatch);
                } catch (Exception ex) {
                  throw new RuntimeException(ex);
                }
              });

      assertTrue(secondScanEntered.await(5, TimeUnit.SECONDS));
      String sessionGetJson =
          "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/call\",\"params\":{\"name\":\"ghidra_bridge\",\"arguments\":{\"operation\":\"get\",\"params\":{}}}}";
      CompletableFuture<HttpResponse<byte[]>> sessionFuture =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  return harness.postRaw(sessionGetJson);
                } catch (Exception ex) {
                  throw new RuntimeException(ex);
                }
              });

      releaseSecondScan.countDown();

      HttpResponse<byte[]> batchResponse = batchFuture.get(5, TimeUnit.SECONDS);
      HttpResponse<byte[]> sessionResponse = sessionFuture.get(5, TimeUnit.SECONDS);

      assertEquals(200, batchResponse.statusCode());
      Map<String, Object> batchToolResult = unwrapResult(batchResponse);
      assertEquals(Boolean.TRUE, batchToolResult.get("isError"));
      @SuppressWarnings("unchecked")
      Map<String, Object> structuredError =
          (Map<String, Object>) batchToolResult.get("structuredContent");
      assertEquals(408, structuredError.get("status"));
      assertEquals("operation_timed_out", structuredError.get("code"));
      @SuppressWarnings("unchecked")
      Map<String, Object> details = (Map<String, Object>) structuredError.get("details");
      assertEquals("scan-2", details.get("failed_item"));
      // scan-0 got 100ms; scan-1 had 40ms left and was clamped to 40ms; scan-2..scan-7 did not run!
      synchronized (observedTimeouts) {
        assertEquals(List.of(100, 40), observedTimeouts);
      }

      assertEquals(200, sessionResponse.statusCode());
      Map<String, Object> sessionResult = unwrapResult(sessionResponse);
      assertEquals(Boolean.FALSE, sessionResult.get("isError"));
    }
  }

  @Test
  void oversizedDirectToolResultIsBoundedInToolResult() throws Exception {
    String hugeText = "z".repeat(McpHttpServer.MAX_TOOL_RESULT_BYTES + 1024);
    CommentService oversizedComments =
        proxy(
            CommentService.class,
            (method, args) ->
                Page.of(
                    List.of(new CommentResource("ram:00100000", CommentResource.Type.EOL, hugeText)),
                    2,
                    null));

    try (TestMcpServer harness =
        startServer(
            unused(MemoryService.class),
            unused(ListingService.class),
            oversizedComments,
            System::nanoTime)) {
      String requestJson =
          "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"ghidra_comment\",\"arguments\":{\"operation\":\"get\",\"params\":{\"selector\":{\"address\":\"ram:00100000\",\"type\":\"eol\"}}}}}";
      HttpResponse<byte[]> response = harness.postRaw(requestJson);
      assertEquals(200, response.statusCode());
      Map<String, Object> toolResult = unwrapResult(response);
      assertEquals(Boolean.TRUE, toolResult.get("isError"));
      @SuppressWarnings("unchecked")
      Map<String, Object> structured = (Map<String, Object>) toolResult.get("structuredContent");
      assertEquals(413, structured.get("status"));
      assertEquals("response_too_large", structured.get("code"));
    }
  }

  private static String buildMemoryBatchRequestJson(int rpcId, int itemCount) {
    List<Map<String, Object>> items = new ArrayList<>(itemCount);
    for (int i = 0; i < itemCount; i++) {
      items.add(
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
    return JsonUtil.toJson(
        Map.of(
            "jsonrpc",
            "2.0",
            "id",
            rpcId,
            "method",
            "tools/call",
            "params",
            Map.of(
                "name",
                "ghidra_batch",
                "arguments",
                Map.of("operation", "execute", "params", Map.of("items", items)))));
  }

  private static String buildScanBatchRequestJson(int rpcId, int itemCount, int timeoutMs) {
    List<Map<String, Object>> items = new ArrayList<>(itemCount);
    for (int i = 0; i < itemCount; i++) {
      items.add(
          Map.of(
              "id",
              "scan-" + i,
              "method",
              "code_unit.list",
              "arguments",
              Map.of(
                  "scan",
                  Map.of(
                      "range",
                      Map.of("start", "ram:00100000", "end", "ram:7fffffff"),
                      "timeout_ms",
                      timeoutMs),
                  "page",
                  Map.of("limit", 10))));
    }
    return JsonUtil.toJson(
        Map.of(
            "jsonrpc",
            "2.0",
            "id",
            rpcId,
            "method",
            "tools/call",
            "params",
            Map.of(
                "name",
                "ghidra_batch",
                "arguments",
                Map.of("operation", "execute", "params", Map.of("items", items)))));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> unwrapResult(HttpResponse<byte[]> response) {
    String body = new String(response.body(), StandardCharsets.UTF_8);
    Map<String, Object> envelope = (Map<String, Object>) JsonUtil.parse(body);
    assertFalse(envelope.containsKey("error"), () -> "Unexpected JSON-RPC error: " + body);
    Map<String, Object> result = (Map<String, Object>) envelope.get("result");
    assertNotNull(result);
    return result;
  }

  private static TestMcpServer startServer(
      MemoryService memory,
      ListingService listing,
      CommentService comments,
      java.util.function.LongSupplier nanoTime)
      throws IOException {
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
            comments,
            unused(ReferenceService.class),
            memory,
            listing,
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactions,
            "mcp-test-program");

    for (int attempt = 0; attempt < 10; attempt++) {
      int port = freeLoopbackPort();
      AgentConfig agentConfig =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "mcp-test-session", null);
      AgentDispatcher dispatcher = new AgentDispatcher(services, agentConfig, nanoTime);
      McpConfig mcpConfig =
          new McpConfig("127.0.0.1", port, "/mcp", null, "mcp-test-session", "ghidra");
      try {
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher);
        server.start();
        return new TestMcpServer(server, dispatcher, URI.create(server.endpoint()));
      } catch (BindException bindCollision) {
        dispatcher.close();
        if (attempt == 9) throw bindCollision;
      }
    }
    throw new AssertionError("Unreachable");
  }

  private static int freeLoopbackPort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private record TestMcpServer(McpHttpServer server, AgentDispatcher dispatcher, URI endpoint)
      implements AutoCloseable {
    private static final HttpClient CLIENT = HttpClient.newHttpClient();

    HttpResponse<byte[]> postRaw(String jsonBody) throws IOException, InterruptedException {
      HttpRequest request =
          HttpRequest.newBuilder(endpoint)
              .header("Content-Type", "application/json")
              .POST(HttpRequest.BodyPublishers.ofString(jsonBody, StandardCharsets.UTF_8))
              .build();
      return CLIENT.send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
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
