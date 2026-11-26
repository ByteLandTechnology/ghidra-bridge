package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
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
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class McpHttpServerConcurrencyTest {

  @Test
  void concurrentFastReadsBypassSlowDecompilationAndSerializeWritesOnHttpThreads()
      throws Exception {
    int port;
    try (ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }

    AtomicInteger concurrentReaders = new AtomicInteger();
    AtomicInteger peakReaders = new AtomicInteger();
    AtomicReference<String> commentText = new AtomicReference<>("initial");
    CountDownLatch slowDecompStarted = new CountDownLatch(1);
    CountDownLatch releaseSlowDecomp = new CountDownLatch(1);

    BridgeServices services =
        createServices(
            concurrentReaders, peakReaders, commentText, slowDecompStarted, releaseSlowDecomp);
    McpConfig mcpConfig = new McpConfig("127.0.0.1", port, "/mcp", null, "mcp-sess", "ghidra");

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "mcp-sess");
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher);
        ExecutorService clientPool = Executors.newFixedThreadPool(24)) {
      server.start();
      HttpClient client = HttpClient.newHttpClient();
      URI uri = URI.create(server.endpoint());

      // Warm up pooled HTTP keep-alive connections and tool codecs across worker threads
      CountDownLatch warmupGate = new CountDownLatch(1);
      List<Future<Map<String, Object>>> warmupCalls = new ArrayList<>();
      for (int i = 0; i < 21; i++) {
        final int idx = i;
        warmupCalls.add(
            clientPool.submit(
                () -> {
                  warmupGate.await();
                  return sendReadVariant(client, uri, "w-" + idx, idx);
                }));
      }
      warmupGate.countDown();
      for (Future<Map<String, Object>> warmupCall : warmupCalls) {
        warmupCall.get(5, TimeUnit.SECONDS);
      }
      peakReaders.set(0);

      // Start one blocked decompilation.get call over HTTP
      Future<Map<String, Object>> slowDecomp =
          clientPool.submit(
              () ->
                  sendToolCall(
                      client,
                      uri,
                      "decomp-1",
                      "ghidra_decompilation",
                      "get",
                      Map.of("selector", Map.of("entry", "ram:00100000"))));
      assertTrue(slowDecompStarted.await(5, TimeUnit.SECONDS));

      // Fire C=20 concurrent fast read HTTP calls while decompilation.get is still in flight
      CountDownLatch launch = new CountDownLatch(1);
      List<Future<Double>> latenciesMs = new ArrayList<>();
      for (int i = 0; i < 20; i++) {
        final int idx = i;
        latenciesMs.add(
            clientPool.submit(
                () -> {
                  launch.await();
                  long start = System.nanoTime();
                  Map<String, Object> body = sendReadVariant(client, uri, "r-" + idx, idx);
                  double elapsedMs = (System.nanoTime() - start) / 1_000_000.0;
                  @SuppressWarnings("unchecked")
                  Map<String, Object> result = (Map<String, Object>) body.get("result");
                  assertEquals(Boolean.FALSE, result.get("isError"));
                  return elapsedMs;
                }));
      }

      launch.countDown();
      List<Double> samples = new ArrayList<>();
      for (Future<Double> future : latenciesMs) {
        samples.add(future.get(5, TimeUnit.SECONDS));
      }
      Collections.sort(samples);
      double p50 = samples.get(samples.size() / 2);

      assertFalse(
          slowDecomp.isDone(),
          "All 20 fast HTTP reads must finish while slow decompilation is still in flight");
      assertTrue(
          peakReaders.get() >= 2,
          "McpHttpServer worker threads must execute reads concurrently, saw peak="
              + peakReaders.get());
      assertTrue(
          p50 < 200.0,
          "Fast read p50 must remain responsive over warm HTTP connections, p50=" + p50 + "ms");

      releaseSlowDecomp.countDown();
      Map<String, Object> decompResp = slowDecomp.get(5, TimeUnit.SECONDS);
      @SuppressWarnings("unchecked")
      Map<String, Object> decompResult = (Map<String, Object>) decompResp.get("result");
      assertEquals(Boolean.FALSE, decompResult.get("isError"));

      // Execute a write over HTTP and verify subsequent HTTP read sees committed value
      Map<String, Object> writeResp =
          sendToolCall(
              client,
              uri,
              "write-1",
              "ghidra_comment",
              "upsert",
              Map.of(
                  "resource",
                  Map.of("address", "ram:00100000", "type", "eol", "text", "committed-via-mcp")));
      @SuppressWarnings("unchecked")
      Map<String, Object> writeResult = (Map<String, Object>) writeResp.get("result");
      assertEquals(Boolean.FALSE, writeResult.get("isError"));

      Map<String, Object> readComment =
          sendToolCall(
              client,
              uri,
              "read-after-write",
              "ghidra_comment",
              "get",
              Map.of("selector", Map.of("address", "ram:00100000", "type", "eol")));
      assertTrue(JsonUtil.toJson(readComment).contains("committed-via-mcp"));
    }
  }

  private static Map<String, Object> sendReadVariant(
      HttpClient client, URI uri, String id, int variant) throws Exception {
    return switch (variant % 5) {
      case 0 -> sendToolCall(client, uri, id, "ghidra_program", "get", Map.of());
      case 1 ->
          sendToolCall(
              client,
              uri,
              id,
              "ghidra_memory",
              "read",
              Map.of("selector", Map.of("address", "ram:00100000"), "length", 16));
      case 2 -> sendToolCall(client, uri, id, "ghidra_bridge", "get", Map.of());
      case 3 -> sendToolCall(client, uri, id, "ghidra_analysis", "get", Map.of());
      default ->
          sendToolCall(
              client,
              uri,
              id,
              "ghidra_batch",
              "execute",
              Map.of(
                  "items",
                  List.of(Map.of("id", "b1", "method", "program.get", "arguments", Map.of()))));
    };
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> sendToolCall(
      HttpClient client,
      URI uri,
      String id,
      String toolName,
      String operation,
      Map<String, Object> params)
      throws Exception {
    String payload =
        JsonUtil.toJson(
            Map.of(
                "jsonrpc",
                "2.0",
                "id",
                id,
                "method",
                "tools/call",
                "params",
                Map.of(
                    "name",
                    toolName,
                    "arguments",
                    Map.of("operation", operation, "params", params))));
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    return (Map<String, Object>) JsonUtil.parse(response.body());
  }

  private static BridgeServices createServices(
      AtomicInteger concurrentReaders,
      AtomicInteger peakReaders,
      AtomicReference<String> commentText,
      CountDownLatch slowDecompStarted,
      CountDownLatch releaseSlowDecomp) {
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              int r = concurrentReaders.incrementAndGet();
              peakReaders.accumulateAndGet(r, Math::max);
              try {
                return new ProgramResource(
                    "mcp-program",
                    "/bin/demo",
                    "ELF",
                    "ram:00100000",
                    "ram:00100000",
                    "ram:0010ffff",
                    "x86:LE:64:default",
                    "gcc",
                    Instant.EPOCH,
                    Instant.EPOCH,
                    10L,
                    20L);
              } finally {
                concurrentReaders.decrementAndGet();
              }
            });
    MemoryService memoryService =
        proxy(
            MemoryService.class,
            (method, args) -> {
              int r = concurrentReaders.incrementAndGet();
              peakReaders.accumulateAndGet(r, Math::max);
              try {
                return new MemoryResource(
                    "ram:00100000", new ByteSequence(ByteSequence.Encoding.HEX, "90".repeat(16), 16));
              } finally {
                concurrentReaders.decrementAndGet();
              }
            });
    AnalysisService analysisService =
        new AnalysisService() {
          @Override
          public AnalysisResource startAnalysis(List<String> analyzers) {
            throw new UnsupportedOperationException();
          }

          @Override
          public AnalysisResource cancelAnalysis() {
            throw new UnsupportedOperationException();
          }

          @Override
          public AnalysisResource getStatus() {
            return new AnalysisResource(
                AnalysisResource.Kind.GHIDRA,
                AnalysisResource.Status.IDLE,
                true,
                null,
                null,
                null,
                null,
                null);
          }

          @Override
          public void close() {}
        };
    DecompilationService decompilationService =
        new DecompilationService() {
          @Override
          public DecompilationResource decompileFunction(
              String rawAddress,
              DecompilationResource.Format format,
              Integer timeoutMs,
              boolean includeComments) {
            int r = concurrentReaders.incrementAndGet();
            peakReaders.accumulateAndGet(r, Math::max);
            slowDecompStarted.countDown();
            try {
              assertTrue(releaseSlowDecomp.await(5, TimeUnit.SECONDS));
              return new DecompilationResource(
                  "ram:00100000",
                  "main",
                  DecompilationResource.Format.TEXT,
                  true,
                  200L,
                  "int main(void) { return 0; }",
                  null,
                  null,
                  null,
                  null,
                  List.of());
            } catch (InterruptedException ex) {
              Thread.currentThread().interrupt();
              throw new IllegalStateException(ex);
            } finally {
              concurrentReaders.decrementAndGet();
            }
          }

          @Override
          public void close() {}
        };
    CommentService commentService =
        new CommentService() {
          @Override
          public Page<CommentResource> listComments(CommentQuery query) {
            ScanProgress progress =
                new ScanProgress(
                    ScanProgress.Kind.ADDRESS,
                    "ram:00100000",
                    "ram:00100000",
                    "ram:00100000",
                    "ram:00100000",
                    true,
                    ScanProgress.StopReason.COMPLETED,
                    0L);
            return Page.scanned(
                List.of(
                    new CommentResource(
                        "ram:00100000", CommentResource.Type.EOL, commentText.get())),
                query.limit(),
                null,
                progress);
          }

          @Override
          public void setComment(String addressRaw, CommentResource.Type type, String text) {
            assertEquals(0, concurrentReaders.get(), "Write must block concurrent reads");
            commentText.set(text);
          }

          @Override
          public void deleteComment(String addressRaw, CommentResource.Type type) {}
        };
    TransactionRunner txRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException ex) {
              throw ex;
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    return new BridgeServices(
        programService,
        unused(AddressService.class),
        commentService,
        unused(ReferenceService.class),
        memoryService,
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysisService,
        decompilationService,
        unused(SymbolService.class),
        unused(DataTypeService.class),
        txRunner,
        "mcp-program");
  }

  private interface Invocation {
    Object invoke(String method, Object[] args) throws Exception;
  }

  private static <T> T unused(Class<T> type) {
    return proxy(type, (method, args) -> {
      throw new AssertionError("Unexpected call: " + method);
    });
  }

  private static <T> T proxy(Class<T> type, Invocation handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> type.getSimpleName();
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(method.getName(), args);
            }));
  }
}
