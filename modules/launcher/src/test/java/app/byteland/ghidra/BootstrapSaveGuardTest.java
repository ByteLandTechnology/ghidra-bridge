package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.program.ProgramServiceImpl;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentWebSocketServer;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.service.BridgeServices;
import com.sun.net.httpserver.HttpServer;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BootstrapSaveGuardTest {

  private String originalHeadlessProperty;

  @BeforeEach
  void saveHeadlessProperty() {
    originalHeadlessProperty = System.getProperty(SystemUtilities.HEADLESS_PROPERTY);
  }

  @AfterEach
  void restoreHeadlessProperty() {
    if (originalHeadlessProperty == null) {
      System.clearProperty(SystemUtilities.HEADLESS_PROPERTY);
    } else {
      System.setProperty(SystemUtilities.HEADLESS_PROPERTY, originalHeadlessProperty);
    }
  }

  private static BridgeServices testBridgeServices(GhidraScript script) {
    GhidraSession session = new GhidraSession(script);
    ProgramServiceImpl programService = new ProgramServiceImpl(session);
    Class<?>[] stubInterfaces = {
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
      app.byteland.ghidra.service.datatype.DataTypeService.class
    };
    Object[] mocks = new Object[stubInterfaces.length];
    for (int i = 0; i < stubInterfaces.length; i++) {
      Class<?> iface = stubInterfaces[i];
      mocks[i] =
          Proxy.newProxyInstance(
              iface.getClassLoader(),
              new Class<?>[] {iface},
              (proxy, method, args) -> {
                if ("close".equals(method.getName())) {
                  return null;
                }
                if ("getStatus".equals(method.getName())) {
                  return new app.byteland.ghidra.service.analysis.AnalysisResource(
                      null,
                      app.byteland.ghidra.service.analysis.AnalysisResource.Status.IDLE,
                      true,
                      null,
                      null,
                      null,
                      null);
                }
                throw new UnsupportedOperationException(method.getName());
              });
    }
    return new BridgeServices(
        programService,
        (app.byteland.ghidra.service.address.AddressService) mocks[0],
        (app.byteland.ghidra.service.comment.CommentService) mocks[1],
        (app.byteland.ghidra.service.reference.ReferenceService) mocks[2],
        (app.byteland.ghidra.service.memory.MemoryService) mocks[3],
        (app.byteland.ghidra.service.listing.ListingService) mocks[4],
        (app.byteland.ghidra.service.function.FunctionService) mocks[5],
        (app.byteland.ghidra.service.globalvariable.GlobalVariableService) mocks[6],
        (app.byteland.ghidra.service.analysis.AnalysisService) mocks[7],
        (app.byteland.ghidra.service.decompilation.DecompilationService) mocks[8],
        (app.byteland.ghidra.service.symbol.SymbolService) mocks[9],
        (app.byteland.ghidra.service.datatype.DataTypeService) mocks[10],
        new app.byteland.ghidra.service.TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            return session.withTransaction(operation::execute);
          }
        },
        session.currentProgram().getName());
  }

  static final class RecordingScript extends GhidraScript {
    private final Program program;
    private final TaskMonitorAdapter taskMonitor = new TaskMonitorAdapter(true);
    private final List<String> stdout = new CopyOnWriteArrayList<>();
    private final List<String> stderr = new CopyOnWriteArrayList<>();
    private final AtomicInteger saveProgramCalls = new AtomicInteger();

    RecordingScript(Program program) {
      this.program = program;
      this.currentProgram = program;
      this.monitor = taskMonitor;
    }

    @Override
    protected void run() {}

    @Override
    public Program getCurrentProgram() {
      return program;
    }

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
      saveProgramCalls.incrementAndGet();
    }

    TaskMonitorAdapter cancellableMonitor() {
      return taskMonitor;
    }

    int saveCount() {
      return saveProgramCalls.get();
    }

    List<String> stdoutLines() {
      return List.copyOf(stdout);
    }

    List<String> stderrLines() {
      return List.copyOf(stderr);
    }
  }

  private static Program stubProgram(String name, boolean inWritableProject, boolean changed) {
    DomainFile domainFile =
        (DomainFile)
            Proxy.newProxyInstance(
                DomainFile.class.getClassLoader(),
                new Class<?>[] {DomainFile.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "isInWritableProject" -> inWritableProject;
                      case "getName" -> name;
                      default -> defaultPrimitiveOrNull(method.getReturnType());
                    });

    FunctionManager functionManager =
        (FunctionManager)
            Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (proxy, method, args) -> defaultPrimitiveOrNull(method.getReturnType()));

    SymbolTable symbolTable =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> defaultPrimitiveOrNull(method.getReturnType()));

    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getName" -> name;
                  case "isChanged" -> changed;
                  case "getDomainFile" -> domainFile;
                  case "getFunctionManager" -> functionManager;
                  case "getSymbolTable" -> symbolTable;
                  case "startTransaction" -> 1;
                  case "endTransaction" -> true;
                  default -> defaultPrimitiveOrNull(method.getReturnType());
                });
  }

  private static Object defaultPrimitiveOrNull(Class<?> returnType) {
    if (!returnType.isPrimitive() || returnType == void.class) {
      return null;
    }
    if (returnType == boolean.class) return false;
    if (returnType == int.class) return 0;
    if (returnType == long.class) return 0L;
    if (returnType == short.class) return (short) 0;
    if (returnType == byte.class) return (byte) 0;
    if (returnType == float.class) return 0.0f;
    if (returnType == double.class) return 0.0d;
    if (returnType == char.class) return '\0';
    return null;
  }

  private static int allocateFreeLoopbackPort() throws IOException {
    try (ServerSocket probe = new ServerSocket()) {
      probe.bind(new InetSocketAddress("127.0.0.1", 0));
      return probe.getLocalPort();
    }
  }

  @Test
  @DisplayName("Bootstrap exposes package-private dependency injection without test hooks")
  void testBootstrapHasNoMutableStaticHooks() {
    for (Field field : Bootstrap.class.getDeclaredFields()) {
      if (Modifier.isStatic(field.getModifiers())) {
        assertTrue(
            Modifier.isFinal(field.getModifiers()),
            () -> "Bootstrap static field must be final: " + field.getName());
      }
    }
    for (Method method : Bootstrap.class.getDeclaredMethods()) {
      assertFalse(
          method.getName().toLowerCase(Locale.ROOT).contains("fortesting"),
          () -> "Bootstrap must not expose test-only hooks: " + method.getName());
    }
  }

  @Test
  @DisplayName("Bootstrap resolves loopback defaults when startup arguments are empty")
  void testEmptyArgsResolveLoopbackDefaults() {
    Program program = stubProgram("sample_binary.elf", true, false);

    Bootstrap.EffectiveConfig wsResolved = Bootstrap.resolveConfig(new String[0], program);
    AgentConfig wsConfig = wsResolved.config();
    assertEquals("127.0.0.1", wsConfig.host());
    assertEquals(8765, wsConfig.port());
    assertEquals("/ws/agent", wsConfig.path());
    assertEquals("sample_binary.elf", wsConfig.sessionId());
    assertEquals(3, wsResolved.defaultMessages().size());

    McpConfig mcpConfig = Bootstrap.resolveMcpConfig(new String[0], program);
    assertEquals("127.0.0.1", mcpConfig.host());
    assertEquals(8766, mcpConfig.port());
    assertEquals("/mcp", mcpConfig.path());
    assertEquals("sample_binary.elf", mcpConfig.sessionId());
    assertEquals("ghidra", mcpConfig.toolPrefix());
  }

  @Test
  @DisplayName("GracefulExit skips saveAction until explicitly activated")
  void testGracefulExitRequiresActivation() throws Exception {
    AtomicInteger saves = new AtomicInteger();
    AtomicInteger succeeded = new AtomicInteger();

    try (GracefulExit disarmed =
        new GracefulExit(saves::incrementAndGet, succeeded::incrementAndGet, err -> {})) {
      assertFalse(disarmed.isSaveActivated());
    }
    assertEquals(0, saves.get(), "Disarmed GracefulExit must not invoke saveAction");
    assertEquals(0, succeeded.get(), "Disarmed GracefulExit must not invoke saveSucceeded");

    try (GracefulExit armed =
        new GracefulExit(saves::incrementAndGet, succeeded::incrementAndGet, err -> {})) {
      armed.activateSave();
      assertTrue(armed.isSaveActivated());
    }
    assertEquals(1, saves.get(), "Activated GracefulExit must invoke saveAction once");
    assertEquals(1, succeeded.get(), "Activated GracefulExit must invoke saveSucceeded once");
  }

  @Test
  @DisplayName("GUI mode skips automatic saves on startup and stop and supports program.save")
  void testGuiModeSkipsAutoSaveAndSupportsExplicitProgramSave() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    int wsPort = allocateFreeLoopbackPort();
    int mcpPort = allocateFreeLoopbackPort();
    String secretToken = "gui-super-secret-token";

    Program wsProgram = stubProgram("gui_ws_target.elf", true, true);
    RecordingScript wsScript = new RecordingScript(wsProgram);
    wsScript.setScriptArgs(new String[] {"host=127.0.0.1", "port=" + wsPort});
    Program mcpProgram = stubProgram("gui_mcp_target.elf", true, true);
    RecordingScript mcpScript = new RecordingScript(mcpProgram);

    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Future<?> wsFuture =
          executor.submit(
              () -> {
                Bootstrap.startFromScript(
                    wsScript, null, null, BootstrapSaveGuardTest::testBridgeServices);
                return null;
              });

      Future<?> mcpFuture =
          executor.submit(
              () -> {
                Bootstrap.startMcpFromScript(
                    mcpScript,
                    new String[] {"host=127.0.0.1", "port=" + mcpPort, "token=" + secretToken},
                    null,
                    BootstrapSaveGuardTest::testBridgeServices);
                return null;
              });

      waitForLogLine(wsScript, "Embedded bridge is listening");
      waitForLogLine(mcpScript, "MCP endpoint is listening");

      assertEquals(0, wsScript.saveCount(), "GUI WebSocket startup must not save the program");
      assertEquals(0, mcpScript.saveCount(), "GUI MCP startup must not save the program");

      // Send an explicit program.save call over MCP and check that manual save runs.
      try (HttpClient httpClient = HttpClient.newHttpClient()) {
        String requestBody =
            """
            {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"ghidra_program","arguments":{"operation":"save","params":{}}}}
            """;
        HttpRequest request =
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + mcpPort + "/mcp"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", "2026-07-28")
                .header("Mcp-Method", "tools/call")
                .header("Mcp-Name", "ghidra_program")
                .header("Authorization", "Bearer " + secretToken)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response =
            httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        assertEquals(200, response.statusCode(), response::body);
        assertFalse(response.body().contains("\"isError\":true"), response::body);
      }
      assertEquals(1, mcpScript.saveCount(), "Explicit program.save must save once in GUI mode");

      wsScript.cancellableMonitor().cancel();
      mcpScript.cancellableMonitor().cancel();
      wsFuture.get(10, TimeUnit.SECONDS);
      mcpFuture.get(10, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }

    assertEquals(0, wsScript.saveCount(), "GUI WebSocket shutdown must not auto-save");
    assertEquals(1, mcpScript.saveCount(), "GUI MCP shutdown must not add an extra auto-save");
    for (String line : mcpScript.stdoutLines()) {
      assertFalse(line.contains(secretToken), "Token value must never appear in console output");
    }
  }

  @Test
  @DisplayName("GUI mode skips saves when socket bind fails")
  void testGuiBindFailureSkipsSaveAndReportsEndpoint() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      Program dirtyProgram = stubProgram("gui_bind_conflict", true, true);
      RecordingScript script = new RecordingScript(dirtyProgram);
      String[] explicitArgs = {"host=127.0.0.1", "port=" + busyPort, "session_id=explicit"};
      script.setScriptArgs(explicitArgs);

      BindException thrown =
          assertThrows(
              BindException.class,
              () ->
                  Bootstrap.startFromScript(
                      script, null, null, BootstrapSaveGuardTest::testBridgeServices));
      assertTrue(thrown.getMessage().contains("ws://127.0.0.1:" + busyPort + "/ws/agent"));
      assertEquals(0, script.saveCount(), "Failed GUI bind must never save the program");
    }
  }

  @Test
  @DisplayName("Headless mode skips saves on failed bind or HTTP 401 and saves after bind or connect")
  void testHeadlessDefersSaveUntilBindOrHandshakeSucceeds() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "true");

    // Check 1: A failed WebSocket or MCP bind in headless mode does not save the program.
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      Program dirtyProgram = stubProgram("headless_fail_bind", false, true);
      RecordingScript failScript = new RecordingScript(dirtyProgram);
      assertThrows(
          BindException.class,
          () ->
              Bootstrap.startFromScript(
                  failScript,
                  new String[] {"port=" + busyPort, "session_id=fail"},
                  null,
                  BootstrapSaveGuardTest::testBridgeServices));
      assertEquals(0, failScript.saveCount(), "Failed headless WS bind must never save");

      RecordingScript failMcpScript = new RecordingScript(dirtyProgram);
      assertThrows(
          BindException.class,
          () ->
              Bootstrap.startMcpFromScript(
                  failMcpScript,
                  new String[] {"port=" + busyPort, "session_id=fail-mcp"},
                  null,
                  BootstrapSaveGuardTest::testBridgeServices));
      assertEquals(0, failMcpScript.saveCount(), "Failed headless MCP bind must never save");
    }

    // Check 2: A failed outbound HTTP 401 handshake in headless mode does not save.
    HttpServer server401 = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server401.createContext(
        "/ws/agent",
        exchange -> {
          exchange.sendResponseHeaders(401, -1);
          exchange.close();
        });
    server401.start();
    try {
      int port401 = server401.getAddress().getPort();
      Program dirtyProgram = stubProgram("headless_fail_401", false, true);
      RecordingScript fail401Script = new RecordingScript(dirtyProgram);
      IOException handshakeEx =
          assertThrows(
              IOException.class,
              () ->
                  Bootstrap.startFromScript(
                      fail401Script,
                      new String[] {
                        "ws_url=ws://127.0.0.1:" + port401 + "/ws/agent", "session_id=fail401"
                      },
                      null,
                      BootstrapSaveGuardTest::testBridgeServices));
      assertTrue(handshakeEx.getMessage().contains("401"));
      assertEquals(0, fail401Script.saveCount(), "Failed headless handshake must never save");
    } finally {
      server401.stop(0);
    }

    // Check 3: An unchanged program in a writable project skips auto-save.
    int unchangedPort = allocateFreeLoopbackPort();
    Program unchangedWritable = stubProgram("headless_unchanged", true, false);
    RecordingScript unchangedScript = new RecordingScript(unchangedWritable);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<?> unchangedFuture =
          executor.submit(
              () -> {
                Bootstrap.startFromScript(
                    unchangedScript,
                    new String[] {"port=" + unchangedPort, "session_id=unchanged"},
                    null,
                    BootstrapSaveGuardTest::testBridgeServices);
                return null;
              });
      waitForLogLine(unchangedScript, "Embedded bridge is listening");
      unchangedScript.cancellableMonitor().cancel();
      unchangedFuture.get(10, TimeUnit.SECONDS);
      assertEquals(
          0, unchangedScript.saveCount(), "Unchanged writable program must skip auto-save");

      // Check 4: A successful headless WebSocket bind saves an imported program.
      int okPort = allocateFreeLoopbackPort();
      Program importedProgram = stubProgram("headless_ok", false, true);
      RecordingScript okScript = new RecordingScript(importedProgram);
      Future<?> okFuture =
          executor.submit(
              () -> {
                Bootstrap.startFromScript(
                    okScript,
                    new String[] {"port=" + okPort, "session_id=ok"},
                    null,
                    BootstrapSaveGuardTest::testBridgeServices);
                return null;
              });
      waitForLogLine(okScript, "Embedded bridge is listening");
      okScript.cancellableMonitor().cancel();
      okFuture.get(10, TimeUnit.SECONDS);
      assertEquals(2, okScript.saveCount(), "Headless WS bind must save at checkpoint and exit");

      // Check 5: A successful headless MCP bind saves an imported program.
      int okMcpPort = allocateFreeLoopbackPort();
      Program importedMcpProgram = stubProgram("headless_mcp_ok", false, true);
      RecordingScript okMcpScript = new RecordingScript(importedMcpProgram);
      Future<?> okMcpFuture =
          executor.submit(
              () -> {
                Bootstrap.startMcpFromScript(
                    okMcpScript,
                    new String[] {"port=" + okMcpPort, "session_id=ok-mcp"},
                    null,
                    BootstrapSaveGuardTest::testBridgeServices);
                return null;
              });
      waitForLogLine(okMcpScript, "MCP endpoint is listening");
      okMcpScript.cancellableMonitor().cancel();
      okMcpFuture.get(10, TimeUnit.SECONDS);
      assertEquals(2, okMcpScript.saveCount(), "Headless MCP bind must save at checkpoint and exit");

      // Check 6: A successful headless outbound handshake saves an imported program.
      int outboundPort = allocateFreeLoopbackPort();
      CountDownLatch readyReceived = new CountDownLatch(1);
      AtomicReference<AgentWebSocketServer.Connection> peerRef = new AtomicReference<>();
      AgentConfig peerConfig =
          new AgentConfig(null, "127.0.0.1", outboundPort, "/ws/agent", null, "peer", null);
      try (AgentWebSocketServer peer =
          new AgentWebSocketServer(
              peerConfig,
              new AgentWebSocketServer.Handler() {
                @Override
                public void onOpen(AgentWebSocketServer.Connection connection) {
                  peerRef.set(connection);
                }

                @Override
                public void onText(AgentWebSocketServer.Connection connection, String message) {
                  if (message.contains("ghidra.ready")) {
                    readyReceived.countDown();
                  }
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
        peer.start();
        Program outboundProgram = stubProgram("headless_outbound_ok", false, true);
        RecordingScript outboundScript = new RecordingScript(outboundProgram);
        Future<?> outboundFuture =
            executor.submit(
                () -> {
                  Bootstrap.startFromScript(
                      outboundScript,
                      new String[] {
                        "ws_url=ws://127.0.0.1:" + outboundPort + "/ws/agent",
                        "session_id=outbound-ok"
                      },
                      null,
                      BootstrapSaveGuardTest::testBridgeServices);
                  return null;
                });
        waitForLogLine(outboundScript, "Outbound bridge connected");
        assertTrue(readyReceived.await(5, TimeUnit.SECONDS), "Expected ghidra.ready notification");
        outboundScript.cancellableMonitor().cancel();
        outboundFuture.get(10, TimeUnit.SECONDS);
        assertEquals(
            2,
            outboundScript.saveCount(),
            "Headless outbound handshake must save at checkpoint and exit");
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  @DisplayName("Generated scripts declare Script Manager metadata and redact URL query strings")
  void testGeneratedScriptMetadataAndRootMessage(@TempDir Path tempClassesDir) throws Exception {
    File generatedBridge =
        Path.of("build", "generated", "scripts", "Bridge.java").toFile().getAbsoluteFile();
    if (!generatedBridge.isFile()) {
      generatedBridge =
          Path.of("modules", "launcher", "build", "generated", "scripts", "Bridge.java")
              .toFile()
              .getAbsoluteFile();
    }
    assertTrue(generatedBridge.isFile(), "Generated Bridge.java must exist");

    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler);
    List<String> options =
        List.of(
            "-proc:none",
            "-classpath",
            System.getProperty("java.class.path"),
            "-d",
            tempClassesDir.toString());
    boolean compiled =
        Boolean.TRUE.equals(
            compiler
                .getTask(
                    null,
                    null,
                    null,
                    options,
                    null,
                    compiler
                        .getStandardFileManager(null, null, null)
                        .getJavaFileObjects(generatedBridge))
                .call());
    assertTrue(compiled, "Generated Bridge.java must compile cleanly");

    File generatedMcp = new File(generatedBridge.getParentFile(), "GhidraMcp.java");
    assertTrue(generatedMcp.isFile(), "Generated GhidraMcp.java must exist");
    var scriptInfoCtor =
        ghidra.app.script.ScriptInfo.class.getDeclaredConstructor(
            ghidra.app.script.GhidraScriptProvider.class, generic.jar.ResourceFile.class);
    scriptInfoCtor.setAccessible(true);
    ghidra.app.script.GhidraScriptProvider provider = new ghidra.app.script.JavaScriptProvider();
    for (File scriptFile : List.of(generatedBridge, generatedMcp)) {
      generic.jar.ResourceFile resourceFile = new generic.jar.ResourceFile(scriptFile);
      ghidra.app.script.ScriptInfo info = scriptInfoCtor.newInstance(provider, resourceFile);
      assertEquals(List.of("Ghidra Bridge"), List.of(info.getCategory()));
      assertFalse(info.getDescription().isBlank(), "Script description must not be blank");
    }

    try (var loader =
        new java.net.URLClassLoader(
            new java.net.URL[] {tempClassesDir.toUri().toURL()},
            GhidraScript.class.getClassLoader())) {
      Class<?> bridgeClass = Class.forName("Bridge", true, loader);
      Object bridgeInstance = bridgeClass.getDeclaredConstructor().newInstance();
      Method rootMessage = bridgeClass.getDeclaredMethod("rootMessage", Throwable.class);
      rootMessage.setAccessible(true);

      Throwable nested401 =
          new InvocationTargetException(
              new IOException(
                  "Failed to connect to ws://127.0.0.1:8765/ws/agent?token=leak-me",
                  new RuntimeException(
                      null, new IllegalStateException("Unexpected HTTP response status code 401"))));

      String formatted = (String) rootMessage.invoke(bridgeInstance, nested401);
      assertEquals(
          "Failed to connect to ws://127.0.0.1:8765/ws/agent?<redacted>:"
              + " Unexpected HTTP response status code 401",
          formatted);
      assertFalse(formatted.contains("leak-me"));
    }
  }

  private static void waitForLogLine(RecordingScript script, String substring) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      for (String line : script.stdoutLines()) {
        if (line.contains(substring)) {
          return;
        }
      }
      Thread.sleep(25);
    }
    throw new AssertionError(
        "Timed out waiting for log '" + substring + "'; got: " + script.stdoutLines());
  }
}
