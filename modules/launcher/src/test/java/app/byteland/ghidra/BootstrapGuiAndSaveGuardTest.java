package app.byteland.ghidra;

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
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Program;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class BootstrapGuiAndSaveGuardTest {
  private final String originalHeadless =
      System.getProperty(SystemUtilities.HEADLESS_PROPERTY);

  @AfterEach
  void restoreHeadlessProperty() {
    if (originalHeadless == null) {
      System.clearProperty(SystemUtilities.HEADLESS_PROPERTY);
    } else {
      System.setProperty(SystemUtilities.HEADLESS_PROPERTY, originalHeadless);
    }
  }

  @Test
  void guiMcpMultiTabAutoSelectsFallbackPortDerivesToolPrefixAndNeverAutoSaves() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    int basePort = findConsecutivePortWindow(4);

    RecordingFixture tab1 = new RecordingFixture("client.exe", true);
    RecordingFixture tab2 = new RecordingFixture("server.elf", true);

    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<?> firstRun =
          pool.submit(
              () -> {
                Bootstrap.startMcpFromScript(
                    tab1.script, new String[0], null, ignored -> tab1.services, basePort);
                return null;
              });
      waitForLogLine(tab1.stdout, "MCP endpoint is listening for HTTP clients.");

      assertTrue(
          tab1.joinedStdout().contains("Endpoint URL: http://127.0.0.1:" + basePort + "/mcp"));
      assertTrue(tab1.joinedStdout().contains("session_id: client.exe"));
      assertTrue(tab1.joinedStdout().contains("tool_prefix: ghidra"));
      assertTrue(
          tab1.joinedStdout().contains("Allowed Origins: loopback and host (default)"));

      Future<?> secondRun =
          pool.submit(
              () -> {
                Bootstrap.startMcpFromScript(
                    tab2.script, new String[0], null, ignored -> tab2.services, basePort);
                return null;
              });
      waitForLogLine(tab2.stdout, "MCP endpoint is listening for HTTP clients.");

      int fallbackPort = basePort + 1;
      String tab2Logs = tab2.joinedStdout();
      assertTrue(tab2Logs.contains("Endpoint URL: http://127.0.0.1:" + fallbackPort + "/mcp"));
      assertTrue(tab2Logs.contains("tool_prefix: server_elf"));
      assertTrue(tab2Logs.contains("session_id: server_elf-" + fallbackPort));
      assertEquals(0, tab2.serviceCloses.get(), "Fallback retry must keep BridgeServices open");

      // Verify live MCP calls succeed on the fallback server with the derived tool_prefix.
      HttpClient httpClient = HttpClient.newHttpClient();
      String fallbackEndpoint = "http://127.0.0.1:" + fallbackPort + "/mcp";
      Map<String, Object> initResponse =
          postJsonRpc(
              httpClient,
              fallbackEndpoint,
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  1,
                  "method",
                  "initialize",
                  "params",
                  Map.of(
                      "protocolVersion",
                      "2025-11-25",
                      "capabilities",
                      Map.of(),
                      "clientInfo",
                      Map.of("name", "gui-tab-test", "version", "1.0"))));
      assertNull(initResponse.get("error"));

      Map<String, Object> callResponse =
          postJsonRpc(
              httpClient,
              fallbackEndpoint,
              Map.of(
                  "jsonrpc",
                  "2.0",
                  "id",
                  2,
                  "method",
                  "tools/call",
                  "params",
                  Map.of(
                      "name",
                      "server_elf_bridge",
                      "arguments",
                      Map.of("operation", "get", "params", Map.of()))));
      @SuppressWarnings("unchecked")
      Map<String, Object> result = (Map<String, Object>) callResponse.get("result");
      assertEquals(Boolean.FALSE, result.get("isError"));
      @SuppressWarnings("unchecked")
      Map<String, Object> structured = (Map<String, Object>) result.get("structuredContent");
      @SuppressWarnings("unchecked")
      Map<String, Object> sessionInfo = (Map<String, Object>) structured.get("result");
      assertEquals("server_elf-" + fallbackPort, sessionInfo.get("id"));
      assertEquals("server.elf", sessionInfo.get("program_name"));

      // Cancel both GUI sessions and confirm neither checkpoint nor GracefulExit saved.
      tab2.monitor.cancel();
      tab1.monitor.cancel();
      secondRun.get(10, TimeUnit.SECONDS);
      firstRun.get(10, TimeUnit.SECONDS);

      assertEquals(0, tab1.checkpointSaves.get());
      assertEquals(0, tab1.exitSaves.get());
      assertEquals(0, tab2.checkpointSaves.get());
      assertEquals(0, tab2.exitSaves.get());
      assertEquals(1, tab1.serviceCloses.get());
      assertEquals(1, tab2.serviceCloses.get());
    } finally {
      tab1.monitor.cancel();
      tab2.monitor.cancel();
      pool.shutdownNow();
    }
  }

  @Test
  void guiWebSocketMultiTabAutoSelectsFallbackPortAndNeverAutoSaves() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    int basePort = findConsecutivePortWindow(4);

    RecordingFixture tab1 = new RecordingFixture("alpha.bin", true);
    RecordingFixture tab2 = new RecordingFixture("beta.bin", true);

    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<?> firstRun =
          pool.submit(
              () -> {
                Bootstrap.startFromScript(
                    tab1.script,
                    new String[0],
                    null,
                    ignored -> tab1.services,
                    basePort,
                    tab1.consoleService);
                return null;
              });
      waitForLogLine(tab1.stdout, "Embedded bridge is listening for WebSocket clients.");

      Future<?> secondRun =
          pool.submit(
              () -> {
                Bootstrap.startFromScript(
                    tab2.script,
                    new String[0],
                    null,
                    ignored -> tab2.services,
                    basePort,
                    tab2.consoleService);
                return null;
              });
      waitForLogLine(tab2.stdout, "Embedded bridge is listening for WebSocket clients.");

      int fallbackPort = basePort + 1;
      assertTrue(
          tab1.joinedStdout()
              .contains("Endpoint URL: ws://127.0.0.1:" + basePort + "/ws/agent"));
      assertTrue(
          tab2.joinedStdout()
              .contains("Endpoint URL: ws://127.0.0.1:" + fallbackPort + "/ws/agent"));
      assertTrue(tab2.joinedStdout().contains("session_id: beta_bin-" + fallbackPort));
      String fallbackToken = tab2.sessionToken();
      assertFalse(tab2.joinedStdout().contains(fallbackToken));

      // Connect a WebSocket client to the fallback tab and verify session.get works.
      try (HttpClient client = HttpClient.newHttpClient()) {
        WsReplyListener listener = new WsReplyListener();
        WebSocket ws =
            client
                .newWebSocketBuilder()
                .header("Authorization", "Bearer " + fallbackToken)
                .buildAsync(
                    URI.create("ws://127.0.0.1:" + fallbackPort + "/ws/agent"), listener)
                .get(5, TimeUnit.SECONDS);
        ws.sendText(
                "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"session.get\",\"params\":{}}",
                true)
            .get(5, TimeUnit.SECONDS);
        String reply = listener.messages.poll(5, TimeUnit.SECONDS);
        assertTrue(reply != null && reply.contains("beta_bin-" + fallbackPort));
        ws.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(5, TimeUnit.SECONDS);
      }

      tab2.monitor.cancel();
      tab1.monitor.cancel();
      secondRun.get(10, TimeUnit.SECONDS);
      firstRun.get(10, TimeUnit.SECONDS);

      assertEquals(0, tab1.checkpointSaves.get());
      assertEquals(0, tab1.exitSaves.get());
      assertEquals(0, tab2.checkpointSaves.get());
      assertEquals(0, tab2.exitSaves.get());
    } finally {
      tab1.monitor.cancel();
      tab2.monitor.cancel();
      pool.shutdownNow();
    }
  }

  @Test
  void headlessAndExplicitPortFailFastWithoutSavingProgram() throws Exception {
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      // Headless explicit port fails fast with endpoint BindException and zero saves.
      System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "true");
      RecordingFixture headlessWs = new RecordingFixture("firmware.bin", true);
      BindException wsBind =
          assertThrows(
              BindException.class,
              () ->
                  Bootstrap.startFromScript(
                      headlessWs.script,
                      new String[] {"port=" + busyPort, "token=headless-secret"},
                      null,
                      ignored -> headlessWs.services,
                      busyPort));
      assertTrue(wsBind.getMessage().contains("ws://127.0.0.1:" + busyPort + "/ws/agent"));
      assertEquals(0, headlessWs.checkpointSaves.get());
      assertEquals(0, headlessWs.exitSaves.get());
      assertEquals(1, headlessWs.serviceCloses.get());

      RecordingFixture headlessMcp = new RecordingFixture("firmware.bin", true);
      BindException mcpBind =
          assertThrows(
              BindException.class,
              () ->
                  Bootstrap.startMcpFromScript(
                      headlessMcp.script,
                      new String[] {"port=" + busyPort},
                      null,
                      ignored -> headlessMcp.services,
                      busyPort));
      assertTrue(mcpBind.getMessage().contains("http://127.0.0.1:" + busyPort + "/mcp"));
      assertEquals(0, headlessMcp.checkpointSaves.get());
      assertEquals(0, headlessMcp.exitSaves.get());
      assertEquals(1, headlessMcp.serviceCloses.get());

      // GUI mode with explicit port= also fails fast without fallback or saves.
      System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
      RecordingFixture guiExplicit = new RecordingFixture("firmware.bin", true);
      assertThrows(
          BindException.class,
          () ->
              Bootstrap.startMcpFromScript(
                  guiExplicit.script,
                  new String[] {"port=" + busyPort},
                  null,
                  ignored -> guiExplicit.services,
                  busyPort));
      assertEquals(0, guiExplicit.checkpointSaves.get());
      assertEquals(0, guiExplicit.exitSaves.get());

      // Headless outbound handshake failure fails before GracefulExit and does not save.
      System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "true");
      Thread rejectOnce =
          new Thread(
              () -> {
                try (var socket = occupied.accept()) {
                  socket
                      .getOutputStream()
                      .write(
                          "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                              .getBytes(StandardCharsets.US_ASCII));
                  socket.getOutputStream().flush();
                } catch (IOException ignored) {
                }
              });
      rejectOnce.setDaemon(true);
      rejectOnce.start();

      RecordingFixture headlessOutbound = new RecordingFixture("firmware.bin", true);
      assertThrows(
          IOException.class,
          () ->
              Bootstrap.startFromScript(
                  headlessOutbound.script,
                  new String[] {"ws_url=ws://127.0.0.1:" + busyPort + "/ws/agent"},
                  null,
                  ignored -> headlessOutbound.services,
                  busyPort));
      assertEquals(0, headlessOutbound.checkpointSaves.get());
      assertEquals(0, headlessOutbound.exitSaves.get());
      assertEquals(1, headlessOutbound.serviceCloses.get());
    }
  }

  @Test
  void headlessSessionSavesOnlyWhenProgramIsChangedAfterSuccessfulBind() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "true");
    int port1 = findConsecutivePortWindow(2);

    // Unchanged headless program never triggers checkpoint or exit saves.
    RecordingFixture unchanged = new RecordingFixture("clean.bin", false);
    ExecutorService pool = Executors.newSingleThreadExecutor();
    try {
      Future<?> run =
          pool.submit(
              () -> {
                Bootstrap.startMcpFromScript(
                    unchanged.script,
                    new String[] {"port=" + port1},
                    null,
                    ignored -> unchanged.services,
                    port1);
                return null;
              });
      waitForLogLine(unchanged.stdout, "MCP endpoint is listening for HTTP clients.");
      unchanged.monitor.cancel();
      run.get(10, TimeUnit.SECONDS);

      assertEquals(0, unchanged.checkpointSaves.get());
      assertEquals(0, unchanged.exitSaves.get());
      assertFalse(unchanged.joinedStdout().contains("Program save on exit completed."));

      // Changed headless program saves checkpoint after bind and saves on exit.
      int port2 = findConsecutivePortWindow(2);
      RecordingFixture dirty = new RecordingFixture("dirty.bin", true);
      Future<?> dirtyRun =
          pool.submit(
              () -> {
                Bootstrap.startMcpFromScript(
                    dirty.script,
                    new String[] {"port=" + port2},
                    null,
                    ignored -> dirty.services,
                    port2);
                return null;
              });
      waitForLogLine(dirty.stdout, "MCP endpoint is listening for HTTP clients.");
      assertEquals(
          1,
          dirty.checkpointSaves.get(),
          "Headless checkpoint save must complete before accepting HTTP requests");
      dirty.monitor.cancel();
      dirtyRun.get(10, TimeUnit.SECONDS);

      assertEquals(1, dirty.checkpointSaves.get());
      assertEquals(1, dirty.exitSaves.get());
      assertTrue(dirty.joinedStdout().contains("Program save on exit completed."));
    } finally {
      pool.shutdownNow();
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> postJsonRpc(
      HttpClient client, String endpoint, Map<String, Object> payload)
      throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(endpoint))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.toJson(payload)))
            .build();
    HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    assertEquals(200, response.statusCode());
    return (Map<String, Object>) JsonUtil.parse(response.body());
  }

  private static void waitForLogLine(List<String> lines, String substring)
      throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      for (String line : lines) {
        if (line.contains(substring)) {
          return;
        }
      }
      Thread.sleep(20L);
    }
    throw new AssertionError("Timed out waiting for log '" + substring + "'; got: " + lines);
  }

  private static int findConsecutivePortWindow(int count) throws IOException {
    for (int attempt = 0; attempt < 20; attempt++) {
      ServerSocket[] sockets = new ServerSocket[count];
      try {
        sockets[0] = new ServerSocket();
        sockets[0].setReuseAddress(true);
        sockets[0].bind(new InetSocketAddress("127.0.0.1", 0));
        int base = sockets[0].getLocalPort();
        if (base + count >= 65535) {
          continue;
        }
        boolean allBound = true;
        for (int i = 1; i < count; i++) {
          sockets[i] = new ServerSocket();
          sockets[i].setReuseAddress(true);
          try {
            sockets[i].bind(new InetSocketAddress("127.0.0.1", base + i));
          } catch (IOException busy) {
            allBound = false;
            break;
          }
        }
        if (allBound) {
          return base;
        }
      } finally {
        for (ServerSocket socket : sockets) {
          if (socket != null) {
            try {
              socket.close();
            } catch (IOException ignored) {
            }
          }
        }
      }
    }
    throw new IllegalStateException("Unable to reserve a consecutive loopback port window");
  }

  private static final class RecordingFixture {
    final AtomicBoolean changed;
    final AtomicInteger checkpointSaves = new AtomicInteger();
    final AtomicInteger exitSaves = new AtomicInteger();
    final AtomicInteger serviceCloses = new AtomicInteger();
    final List<String> stdout = new CopyOnWriteArrayList<>();
    final List<String> stderr = new CopyOnWriteArrayList<>();
    final List<String> console = new CopyOnWriteArrayList<>();
    final ConsoleService consoleService;
    final TaskMonitorAdapter monitor = new TaskMonitorAdapter(true);
    final Program program;
    final BridgeServices services;
    final GhidraScript script;

    RecordingFixture(String programName, boolean initiallyChanged) {
      this.changed = new AtomicBoolean(initiallyChanged);
      this.program =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getName" -> programName;
                        case "isChanged" -> changed.get();
                        default -> throw new UnsupportedOperationException(method.getName());
                      });
      ProgramService programService =
          (ProgramService)
              Proxy.newProxyInstance(
                  ProgramService.class.getClassLoader(),
                  new Class<?>[] {ProgramService.class},
                  (proxy, method, args) -> {
                    if ("saveProgram".equals(method.getName())) {
                      exitSaves.incrementAndGet();
                      return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
                  });
      AnalysisService analysisService = closeTrackingStub(AnalysisService.class);
      DecompilationService decompilationService =
          (DecompilationService)
              Proxy.newProxyInstance(
                  DecompilationService.class.getClassLoader(),
                  new Class<?>[] {DecompilationService.class},
                  (proxy, method, args) -> {
                    if ("close".equals(method.getName())) {
                      serviceCloses.incrementAndGet();
                      return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
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
      this.services =
          new BridgeServices(
              programService,
              unused(AddressService.class),
              unused(CommentService.class),
              unused(ReferenceService.class),
              unused(MemoryService.class),
              unused(ListingService.class),
              unused(FunctionService.class),
              unused(GlobalVariableService.class),
              analysisService,
              decompilationService,
              unused(SymbolService.class),
              unused(DataTypeService.class),
              transactionRunner,
              programName);
      this.consoleService =
          (ConsoleService)
              Proxy.newProxyInstance(
                  ConsoleService.class.getClassLoader(),
                  new Class<?>[] {ConsoleService.class},
                  (proxy, method, args) -> {
                    if ("println".equals(method.getName()) && args != null && args.length == 1) {
                      console.add((String) args[0]);
                    }
                    return null;
                  });
      this.script =
          new GhidraScript() {
            {
              set(RecordingFixture.this.program, RecordingFixture.this.monitor);
            }

            @Override
            protected void run() {}

            @Override
            public void println(String message) {
              stdout.add(message);
            }

            @Override
            public void printerr(String message) {
              stderr.add(message);
            }

            @Override
            public void saveProgram(Program target) {
              checkpointSaves.incrementAndGet();
            }
          };
    }

    String joinedStdout() {
      return String.join("\n", stdout);
    }

    String sessionToken() {
      String prefix = "[ghidra-bridge]   Session Token: ";
      for (String line : console) {
        if (line.startsWith(prefix)) {
          return line.substring(prefix.length());
        }
      }
      throw new AssertionError("Expected generated Session Token in GUI console, got: " + console);
    }

    private static <T> T closeTrackingStub(Class<T> type) {
      return type.cast(
          Proxy.newProxyInstance(
              type.getClassLoader(),
              new Class<?>[] {type},
              (proxy, method, args) -> {
                if ("close".equals(method.getName())) {
                  return null;
                }
                throw new UnsupportedOperationException(method.getName());
              }));
    }

    private static <T> T unused(Class<T> type) {
      return type.cast(
          Proxy.newProxyInstance(
              type.getClassLoader(),
              new Class<?>[] {type},
              (proxy, method, args) -> {
                throw new UnsupportedOperationException(method.getName());
              }));
    }
  }

  private static final class WsReplyListener implements WebSocket.Listener {
    final BlockingQueue<String> messages = new LinkedBlockingQueue<>();
    private final StringBuilder buffer = new StringBuilder();

    @Override
    public void onOpen(WebSocket webSocket) {
      webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
      buffer.append(data);
      if (last) {
        messages.add(buffer.toString());
        buffer.setLength(0);
      }
      webSocket.request(1);
      return CompletableFuture.completedFuture(null);
    }
  }
}
