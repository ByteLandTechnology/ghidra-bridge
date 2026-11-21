package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.program.ProgramServiceImpl;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.service.BridgeServices;
import com.sun.net.httpserver.HttpServer;
import docking.widgets.values.GValuesMap;
import docking.widgets.values.ValuesMapDialog;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.MessageType;
import ghidra.util.StatusListener;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BootstrapAndGuiDialogTest {

  private String originalHeadlessProperty;

  @BeforeEach
  void saveHeadlessProperty() {
    originalHeadlessProperty = System.getProperty(SystemUtilities.HEADLESS_PROPERTY);
    GuiConfigDialog.resetForTesting();
    Bootstrap.setServiceFactoryForTesting(BootstrapAndGuiDialogTest::testBridgeServices);
  }

  @AfterEach
  void restoreHeadlessProperty() {
    Bootstrap.setServiceFactoryForTesting(null);
    GuiConfigDialog.resetForTesting();
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
  @DisplayName("Port and tool_prefix defaults handle single-tab and multi-tab collisions")
  void testMultiTabDefaultsPreFillFreePortAndToolPrefix() {
    Program firstProgram = stubProgram("firmware.v1.bin", true, false);
    Program secondProgram = stubProgram("firmware.v2.bin", true, false);
    Program numericProgram = stubProgram("123-loader.exe", true, false);
    Program ghidraNamedProgram = stubProgram("ghidra", true, false);

    // WebSocket skips MCP default port 8766 when 8765 is busy.
    int wsPortWhen8765Busy =
        GuiConfigDialog.findFreePort(
            "127.0.0.1", 8765, Set.of(8766), candidate -> candidate != 8765);
    assertEquals(8767, wsPortWhen8765Busy);

    // MCP first tab uses 8766 and tool_prefix=ghidra.
    String firstPrefix = GuiConfigDialog.defaultGuiToolPrefix(firstProgram, 8766, Set.of());
    assertEquals("ghidra", firstPrefix);

    // MCP second tab when 8766 is busy derives a valid program-based tool_prefix.
    String secondPrefix =
        GuiConfigDialog.defaultGuiToolPrefix(secondProgram, 8767, Set.of("ghidra"));
    assertEquals("firmware_v2_bin", secondPrefix);

    // Program starting with digits gets a valid letter prefix.
    String numericPrefix =
        GuiConfigDialog.defaultGuiToolPrefix(numericProgram, 8768, Set.of("ghidra"));
    assertEquals("ghidra_123-loader_exe", numericPrefix);

    // Program named 'ghidra' on a secondary port avoids colliding with 'ghidra'.
    String disambiguatedPrefix =
        GuiConfigDialog.defaultGuiToolPrefix(ghidraNamedProgram, 8769, Set.of("ghidra"));
    assertEquals("ghidra_8769", disambiguatedPrefix);

    // Duplicate session_id across open tabs is disambiguated.
    assertEquals(
        "firmware.v1.bin-2",
        GuiConfigDialog.defaultGuiSessionId(firstProgram, Set.of("firmware.v1.bin")));
  }

  @Test
  @DisplayName("GUI dialogs expose all documented keys, mask tokens, and validate inputs inline")
  void testDialogFieldsMaskingAndInlineValidation() throws Exception {
    Program program = stubProgram("target_app", true, false);
    GuiConfigDialog.WebSocketDefaults wsDefaults =
        new GuiConfigDialog.WebSocketDefaults("127.0.0.1", 8765, "/ws/agent", "target_app");
    ValuesMapDialog wsDialog = GuiConfigDialog.createWebSocketDialog(program, wsDefaults);
    GValuesMap wsValues = wsDialog.getValues();

    assertTrue(wsValues.isDefined("host"));
    assertTrue(wsValues.isDefined("port"));
    assertTrue(wsValues.isDefined("path"));
    assertTrue(wsValues.isDefined("session_id"));
    assertTrue(wsValues.isDefined("token"));
    assertTrue(wsValues.isDefined("ws_url"));
    assertTrue(wsValues.isDefined("exit_deadline_sec"));

    // Token component must be a masked JPasswordField and redact text conversion.
    var tokenAbstractValue = wsValues.getAbstractValue("token");
    assertInstanceOf(JPasswordField.class, tokenAbstractValue.getComponent());
    wsValues.setString("token", "my-secret-value");
    assertEquals("<redacted>", tokenAbstractValue.getAsText());

    // Setting ws_url in the UI automatically disables host/port/path fields and builds outbound AgentConfig.
    JTextField wsUrlField = (JTextField) wsValues.getAbstractValue("ws_url").getComponent();
    wsUrlField.setText("ws://127.0.0.1:9999/ws/agent");
    assertFalse(wsValues.getAbstractValue("host").getComponent().isEnabled());
    assertFalse(wsValues.getAbstractValue("port").getComponent().isEnabled());
    assertFalse(wsValues.getAbstractValue("path").getComponent().isEnabled());
    wsValues.updateFromComponents();
    AgentConfig outbound = GuiConfigDialog.parseWebSocketValues(wsValues, wsDefaults);
    assertTrue(outbound.isOutboundMode());
    assertEquals("ws://127.0.0.1:9999/ws/agent", outbound.wsUrl());
    assertNull(outbound.port());

    // Validator rejects non-loopback host without token and reports inline error message.
    wsUrlField.setText("");
    ((JPasswordField) tokenAbstractValue.getComponent()).setText("");
    ((JTextField) wsValues.getAbstractValue("host").getComponent()).setText("0.0.0.0");
    wsValues.updateFromComponents();
    AtomicReference<String> errorBanner = new AtomicReference<>();
    StatusListener status =
        new StatusListener() {
          @Override
          public void setStatusText(String text) {
            errorBanner.set(text);
          }

          @Override
          public void setStatusText(String text, MessageType type) {
            errorBanner.set(text);
          }

          @Override
          public void setStatusText(String text, MessageType type, boolean alert) {
            errorBanner.set(text);
          }

          @Override
          public void clearStatusText() {
            errorBanner.set(null);
          }
        };
    assertFalse(wsValues.isValid(status));
    assertNotNull(errorBanner.get());
    assertTrue(errorBanner.get().contains("token is required"));

    // Invalid ws_url with secret query string never leaks query string in validation message.
    wsUrlField.setText("http://127.0.0.1:9999/not-ws?secret=do-not-leak");
    wsValues.updateFromComponents();
    assertFalse(wsValues.isValid(status));
    assertFalse(errorBanner.get().contains("do-not-leak"));

    // MCP dialog exposes all documented MCP keys and validates tool_prefix.
    GuiConfigDialog.McpDefaults mcpDefaults =
        new GuiConfigDialog.McpDefaults("127.0.0.1", 8766, "/mcp", "target_app", "ghidra");
    ValuesMapDialog mcpDialog = GuiConfigDialog.createMcpDialog(program, mcpDefaults);
    GValuesMap mcpValues = mcpDialog.getValues();
    assertTrue(mcpValues.isDefined("host"));
    assertTrue(mcpValues.isDefined("port"));
    assertTrue(mcpValues.isDefined("path"));
    assertTrue(mcpValues.isDefined("session_id"));
    assertTrue(mcpValues.isDefined("tool_prefix"));
    assertTrue(mcpValues.isDefined("token"));

    ((JTextField) mcpValues.getAbstractValue("tool_prefix").getComponent()).setText("99invalid");
    mcpValues.updateFromComponents();
    assertFalse(mcpValues.isValid(status));
    assertTrue(errorBanner.get().contains("tool_prefix"));
  }

  @Test
  @DisplayName("Canceling GUI dialog exits Bootstrap cleanly without errors or saves")
  void testGuiDialogCancelExitsCleanlyWithoutSaves() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    Program dirtyGuiProgram = stubProgram("dirty_gui_binary", true, true);
    RecordingScript wsScript = new RecordingScript(dirtyGuiProgram);
    RecordingScript mcpScript = new RecordingScript(dirtyGuiProgram);

    AtomicInteger dialogShownCount = new AtomicInteger();
    GuiConfigDialog.setPresenterForTesting(
        (kind, dialog) -> {
          dialogShownCount.incrementAndGet();
          return false;
        });

    Bootstrap.startFromScript(wsScript, new String[0], () -> {});
    Bootstrap.startMcpFromScript(mcpScript, new String[0], () -> {});

    assertEquals(2, dialogShownCount.get());
    assertEquals(0, wsScript.saveCount(), "GUI cancel must never save program");
    assertEquals(0, mcpScript.saveCount(), "GUI cancel must never save program");
    assertTrue(wsScript.stderrLines().isEmpty(), "GUI cancel must not write stderr");
    assertTrue(mcpScript.stderrLines().isEmpty(), "GUI cancel must not write stderr");
    assertTrue(wsScript.stdoutLines().isEmpty(), "GUI cancel must exit silently");
    assertTrue(mcpScript.stdoutLines().isEmpty(), "GUI cancel must exit silently");
  }

  @Test
  @DisplayName("GUI mode runs concurrent multi-tab MCP sessions on free ports and never auto-saves")
  void testConcurrentGuiMcpTabsPreFillFreePortAndNeverAutoSave() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    Program tab1Program = stubProgram("tab_one.elf", true, true);
    Program tab2Program = stubProgram("tab_two.elf", true, true);
    RecordingScript tab1Script = new RecordingScript(tab1Program);
    RecordingScript tab2Script = new RecordingScript(tab2Program);

    CountDownLatch tab1Listening = new CountDownLatch(1);
    CountDownLatch tab2Listening = new CountDownLatch(1);
    List<Integer> presentedPorts = new CopyOnWriteArrayList<>();
    List<String> presentedPrefixes = new CopyOnWriteArrayList<>();

    GuiConfigDialog.setPresenterForTesting(
        (kind, dialog) -> {
          GValuesMap map = dialog.getValues();
          presentedPorts.add(Integer.parseInt(map.getString("port")));
          presentedPrefixes.add(map.getString("tool_prefix"));
          // Set a secret token on tab 2 to verify log redaction as well.
          if (presentedPorts.size() == 2) {
            map.setString("token", "tab2-super-secret-token");
          }
          return true;
        });

    ExecutorService executor = Executors.newFixedThreadPool(2);
    try {
      Future<?> tab1Future =
          executor.submit(
              () -> {
                Bootstrap.startMcpFromScript(tab1Script, new String[0], null);
                return null;
              });

      waitForLogLine(tab1Script, "MCP endpoint is listening", tab1Listening);

      Future<?> tab2Future =
          executor.submit(
              () -> {
                Bootstrap.startMcpFromScript(tab2Script, new String[0], null);
                return null;
              });

      waitForLogLine(tab2Script, "MCP endpoint is listening", tab2Listening);

      assertEquals(2, presentedPorts.size());
      assertNotEquals(
          presentedPorts.get(0),
          presentedPorts.get(1),
          "Second tab must pre-fill a free non-colliding port");
      assertEquals("tab_two_elf", presentedPrefixes.get(1));

      tab1Script.cancellableMonitor().cancel();
      tab2Script.cancellableMonitor().cancel();
      tab1Future.get(10, TimeUnit.SECONDS);
      tab2Future.get(10, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }

    assertEquals(0, tab1Script.saveCount(), "Interactive GUI tab 1 must never auto-save");
    assertEquals(0, tab2Script.saveCount(), "Interactive GUI tab 2 must never auto-save");
    for (String line : tab2Script.stdoutLines()) {
      assertFalse(line.contains("tab2-super-secret-token"), "Token value must never be logged");
    }
  }

  @Test
  @DisplayName("GUI mode bypasses dialog when getScriptArgs() is non-empty and skips save on bind failure")
  void testGuiWithExplicitArgsBypassesDialogAndSkipsSaveOnBindFailure() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "false");
    AtomicBoolean dialogOpened = new AtomicBoolean(false);
    GuiConfigDialog.setPresenterForTesting(
        (kind, dialog) -> {
          dialogOpened.set(true);
          return false;
        });

    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      Program dirtyProgram = stubProgram("companion_script_target", true, true);
      RecordingScript script = new RecordingScript(dirtyProgram);
      String[] explicitArgs = {"host=127.0.0.1", "port=" + busyPort, "session_id=explicit"};
      script.setScriptArgs(explicitArgs);

      BindException thrown =
          assertThrows(
              BindException.class,
              () -> Bootstrap.startFromScript(script, script.getScriptArgs(), null));
      assertTrue(thrown.getMessage().contains("ws://127.0.0.1:" + busyPort + "/ws/agent"));
      assertFalse(dialogOpened.get(), "Non-empty scriptArgs must bypass GUI dialog");
      assertEquals(0, script.saveCount(), "Failed GUI bind must never save program");
    }
  }

  @Test
  @DisplayName("Headless mode skips saves on failed bind or HTTP 401 and saves only after successful bind")
  void testHeadlessDefersSaveUntilBindOrHandshakeSucceeds() throws Exception {
    System.setProperty(SystemUtilities.HEADLESS_PROPERTY, "true");

    // 1. Failed WebSocket bind in headless mode must NEVER save.
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();

      Program dirtyProgram = stubProgram("headless_fail_bind", false, true);
      RecordingScript failScript = new RecordingScript(dirtyProgram);
      assertThrows(
          BindException.class,
          () ->
              Bootstrap.startFromScript(
                  failScript, new String[] {"port=" + busyPort, "session_id=fail"}, null));
      assertEquals(0, failScript.saveCount(), "Failed headless bind must never save program");
    }

    // 2. Failed outbound HTTP 401 handshake in headless mode must NEVER save.
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
                      null));
      assertTrue(handshakeEx.getMessage().contains("401"));
      assertEquals(0, fail401Script.saveCount(), "Failed headless handshake must never save");
    } finally {
      server401.stop(0);
    }

    // 3. Successful headless bind activates checkpoint and GracefulExit save.
    int freePort;
    try (ServerSocket probe = new ServerSocket()) {
      probe.bind(new InetSocketAddress("127.0.0.1", 0));
      freePort = probe.getLocalPort();
    }
    Program importedProgram = stubProgram("headless_ok", false, true);
    RecordingScript okScript = new RecordingScript(importedProgram);
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<?> runFuture =
          executor.submit(
              () -> {
                Bootstrap.startFromScript(
                    okScript, new String[] {"port=" + freePort, "session_id=ok"}, null);
                return null;
              });
      waitForLogLine(okScript, "Embedded bridge is listening", new CountDownLatch(1));
      okScript.cancellableMonitor().cancel();
      runFuture.get(10, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }
    assertTrue(okScript.saveCount() >= 1, "Successful headless run must save imported program");
  }

  @Test
  @DisplayName("Generated Bridge.java preserves nested causes and redacts query strings in rootMessage")
  void testGeneratedScriptRootMessagePreservesNestedCausesAndRedactsSecrets(
      @TempDir Path tempClassesDir) throws Exception {
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
      assertArrayEqualsCompat(new String[] {"Ghidra Bridge"}, info.getCategory());
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

  private static void assertArrayEqualsCompat(String[] expected, String[] actual) {
    assertEquals(List.of(expected), List.of(actual));
  }

  private static void waitForLogLine(
      RecordingScript script, String substring, CountDownLatch unused) throws Exception {
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
