package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentWebSocketServer;
import app.byteland.ghidra.mcp.McpConfig;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GhidraLauncherPromptTest {

  @TempDir Path tempDir;

  @Test
  void guiPromptUsesPrefilledDefaultsAndParsesEnteredKeyValueArguments() throws Exception {
    HarnessClasses harness = compileHarnessClasses();

    ScriptHarness mcpScript =
        harness.newScript(
            "GhidraMcp",
            false,
            new String[0],
            (title, message, defaultValue) -> {
              assertEquals("GhidraMcp Startup Arguments", title);
              assertEquals("host=127.0.0.1 path=/mcp tool_prefix=ghidra", defaultValue);
              return "host=127.0.0.1 port=9123 token=sec123 tool_prefix=fw_two"
                  + " jar=\"/tmp/with space/ghidra-bridge.jar\"";
            });
    assertArrayEquals(
        new String[] {
          "host=127.0.0.1",
          "port=9123",
          "token=sec123",
          "tool_prefix=fw_two",
          "jar=/tmp/with space/ghidra-bridge.jar"
        },
        mcpScript.invokeResolveStartupArgs());
    assertEquals(1, mcpScript.promptCount());

    ScriptHarness bridgeScript =
        harness.newScript(
            "Bridge",
            false,
            new String[0],
            (title, message, defaultValue) -> {
              assertEquals("Bridge Startup Arguments", title);
              assertEquals("host=127.0.0.1 path=/ws/agent", defaultValue);
              return "ws_url=ws://127.0.0.1:18489/ws/agent session_id=0123456789abcdef0123456789abcdef"
                  + " token=attach-secret";
            });
    assertArrayEquals(
        new String[] {
          "ws_url=ws://127.0.0.1:18489/ws/agent",
          "session_id=0123456789abcdef0123456789abcdef",
          "token=attach-secret"
        },
        bridgeScript.invokeResolveStartupArgs());
    assertEquals(1, bridgeScript.promptCount());
  }

  @Test
  void cancellingGuiPromptExitsCleanlyWithoutStartingListenerOrPrintingErrors() throws Exception {
    HarnessClasses harness = compileHarnessClasses();
    Path missingJarDir = tempDir.resolve("no-jar-needed-on-cancel");
    Files.createDirectories(missingJarDir);

    for (String className : new String[] {"Bridge", "GhidraMcp"}) {
      ScriptHarness script =
          harness.newScript(
              className,
              false,
              new String[0],
              (title, message, defaultValue) -> {
                throw new CancelledException();
              });
      script.invokeRun();

      assertEquals(1, script.promptCount());
      assertEquals(List.of(), script.errorLines(), "Cancel must not write startup error lines");
      assertTrue(
          script.outputLines().stream().anyMatch(line -> line.contains("Startup cancelled.")),
          "Expected clean cancel log message, got: " + script.outputLines());
    }
  }

  @Test
  void headlessModeAndExplicitScriptArgumentsSkipInteractivePrompt() throws Exception {
    HarnessClasses harness = compileHarnessClasses();

    ScriptHarness headlessEmpty =
        harness.newScript(
            "GhidraMcp",
            true,
            new String[0],
            (title, message, defaultValue) -> {
              throw new AssertionError("Headless run must not open askString");
            });
    assertArrayEquals(new String[0], headlessEmpty.invokeResolveStartupArgs());
    assertEquals(0, headlessEmpty.promptCount());

    String[] explicit =
        new String[] {"jar=/tmp/my folder/ghidra-bridge.jar", "port=8766", "session_id=ci"};
    ScriptHarness guiWithExplicitArgs =
        harness.newScript(
            "GhidraMcp",
            false,
            explicit,
            (title, message, defaultValue) -> {
              throw new AssertionError("Explicit script args must skip askString");
            });
    assertArrayEquals(explicit, guiWithExplicitArgs.invokeResolveStartupArgs());
    assertEquals(0, guiWithExplicitArgs.promptCount());
  }

  @Test
  void launcherAppliesGuiJarAndOutboundArgumentsEndToEnd() throws Exception {
    HarnessClasses harness = compileHarnessClasses();
    Path runtimeJar = buildFullRuntimeJar(tempDir.resolve("ghidra-bridge.jar"));

    BlockingQueue<String> inboundMessages = new LinkedBlockingQueue<>();
    CountDownLatch connectedLatch = new CountDownLatch(1);
    AgentWebSocketServer.Handler serverHandler =
        new AgentWebSocketServer.Handler() {
          @Override
          public void onOpen(AgentWebSocketServer.Connection connection) {}

          @Override
          public void onText(AgentWebSocketServer.Connection connection, String message) {
            inboundMessages.add(message);
            connectedLatch.countDown();
          }

          @Override
          public void onClose(
              AgentWebSocketServer.Connection connection, int statusCode, String reason) {}

          @Override
          public void onConnectionError(
              AgentWebSocketServer.Connection connection, Throwable error) {}

          @Override
          public void onServerError(Throwable error) {}
        };

    int daemonPort = findFreePort();
    String token = "gui-attach-token";
    String sessionId = "0123456789abcdef0123456789abcdef";
    AgentConfig daemonConfig =
        new AgentConfig(null, "127.0.0.1", daemonPort, "/ws/agent", token, sessionId, null);

    AtomicBoolean cancelBridge = new AtomicBoolean(false);
    try (AgentWebSocketServer daemonWs = new AgentWebSocketServer(daemonConfig, serverHandler);
        ExecutorService executor = Executors.newSingleThreadExecutor()) {
      daemonWs.start();

      ScriptHarness bridgeScript =
          harness.newScript(
              "Bridge",
              false,
              new String[0],
              (title, message, defaultValue) ->
                  "ws_url=ws://127.0.0.1:"
                      + daemonWs.port()
                      + "/ws/agent session_id="
                      + sessionId
                      + " token="
                      + token
                      + " jar=\""
                      + runtimeJar.toAbsolutePath()
                      + "\"");
      configureFakeProgramAndMonitor(bridgeScript.instance(), "gui-binary.elf", cancelBridge);

      Future<?> runFuture =
          executor.submit(
              () -> {
                bridgeScript.invokeRun();
                return null;
              });

      awaitLatchOrFutureFailure(connectedLatch, runFuture, "Expected outbound ghidra.ready");
      String readyJson = inboundMessages.poll(5, TimeUnit.SECONDS);
      assertNotNull(readyJson);
      assertTrue(readyJson.contains("\"ghidra.ready\""), readyJson);
      assertTrue(readyJson.contains(sessionId), readyJson);

      cancelBridge.set(true);
      runFuture.get(10, TimeUnit.SECONDS);
      assertFalse(
          bridgeScript.outputLines().stream().anyMatch(line -> line.contains(token)),
          "Console output must never leak bearer token");
    }
  }

  @Test
  void bootstrapSecondBinarySelectsNextFreePortAndLogsActiveEndpointWhileExplicitPortFailsFast()
      throws Exception {
    AtomicBoolean cancelFirst = new AtomicBoolean(false);
    AtomicBoolean cancelSecond = new AtomicBoolean(false);
    List<String> firstLogs = new CopyOnWriteArrayList<>();
    List<String> secondLogs = new CopyOnWriteArrayList<>();

    GhidraScript firstScript =
        fakeGhidraScript("first.elf", cancelFirst, firstLogs, new CopyOnWriteArrayList<>());
    GhidraScript secondScript =
        fakeGhidraScript("second.elf", cancelSecond, secondLogs, new CopyOnWriteArrayList<>());

    try (ServerSocket defaultPortBlocker = bindIfAvailable(McpConfig.DEFAULT_PORT);
        ExecutorService executor = Executors.newFixedThreadPool(2)) {
      Future<?> firstFuture =
          executor.submit(
              () -> {
                Bootstrap.startMcpFromScript(firstScript, new String[0], () -> {});
                return null;
              });
      String firstEndpoint = awaitLoggedEndpoint(firstLogs, "[ghidra-mcp]   Endpoint: ", firstFuture);
      int firstPort = URI.create(firstEndpoint).getPort();

      Future<?> secondFuture =
          executor.submit(
              () -> {
                Bootstrap.startMcpFromScript(secondScript, new String[0], () -> {});
                return null;
              });
      String secondEndpoint =
          awaitLoggedEndpoint(secondLogs, "[ghidra-mcp]   Endpoint: ", secondFuture);
      int secondPort = URI.create(secondEndpoint).getPort();
      assertTrue(
          secondPort > firstPort,
          "Second binary must bind a higher port than " + firstPort + ", got " + secondPort);

      HttpClient httpClient = HttpClient.newHttpClient();
      HttpResponse<String> response =
          httpClient.send(
              HttpRequest.newBuilder(URI.create(secondEndpoint))
                  .header("Content-Type", "application/json")
                  .POST(
                      HttpRequest.BodyPublishers.ofString(
                          "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}"))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      assertEquals(200, response.statusCode());

      GhidraScript explicitConflictScript =
          fakeGhidraScript(
              "conflict.elf",
              new AtomicBoolean(false),
              new CopyOnWriteArrayList<>(),
              new CopyOnWriteArrayList<>());
      assertThrows(
          BindException.class,
          () ->
              Bootstrap.startMcpFromScript(
                  explicitConflictScript, new String[] {"port=" + firstPort}, () -> {}));

      cancelSecond.set(true);
      cancelFirst.set(true);
      secondFuture.get(10, TimeUnit.SECONDS);
      firstFuture.get(10, TimeUnit.SECONDS);
      assertNotNull(defaultPortBlocker == null ? Boolean.TRUE : defaultPortBlocker);
    }
  }

  private static void awaitLatchOrFutureFailure(
      CountDownLatch latch, Future<?> future, String failureMessage) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      if (latch.await(25L, TimeUnit.MILLISECONDS)) {
        return;
      }
      if (future.isDone()) {
        future.get();
        break;
      }
    }
    throw new AssertionError(failureMessage);
  }

  private static String awaitLoggedEndpoint(List<String> logs, String prefix, Future<?> future)
      throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      for (String line : logs) {
        if (line.startsWith(prefix)) {
          return line.substring(prefix.length()).trim();
        }
      }
      if (future.isDone()) {
        future.get();
        break;
      }
      Thread.sleep(25L);
    }
    throw new AssertionError("Timed out waiting for log line with prefix '" + prefix + "': " + logs);
  }

  private static ServerSocket bindIfAvailable(int port) {
    ServerSocket socket = null;
    try {
      socket = new ServerSocket();
      socket.bind(new InetSocketAddress("127.0.0.1", port));
      return socket;
    } catch (IOException alreadyBusy) {
      if (socket != null) {
        try {
          socket.close();
        } catch (IOException ignored) {
        }
      }
      return null;
    }
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      return socket.getLocalPort();
    }
  }

  private static GhidraScript fakeGhidraScript(
      String programName,
      AtomicBoolean cancelled,
      List<String> outLines,
      List<String> errLines)
      throws Exception {
    GhidraScript script =
        new GhidraScript() {
          @Override
          protected void run() {}

          @Override
          public void println(String message) {
            outLines.add(message);
          }

          @Override
          public void printerr(String message) {
            errLines.add(message);
          }

          @Override
          public void saveProgram(Program program) {}
        };
    configureFakeProgramAndMonitor(script, programName, cancelled);
    return script;
  }

  private static void configureFakeProgramAndMonitor(
      GhidraScript script, String programName, AtomicBoolean cancelled) throws Exception {
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                new FakeProgramHandler(programName));
    TaskMonitor monitor =
        (TaskMonitor)
            Proxy.newProxyInstance(
                TaskMonitor.class.getClassLoader(),
                new Class<?>[] {TaskMonitor.class},
                (proxy, method, args) -> {
                  if ("isCancelled".equals(method.getName())) {
                    return cancelled.get();
                  }
                  return defaultReturn(method.getReturnType());
                });
    setField(FlatProgramAPI.class, script, "currentProgram", program);
    setField(FlatProgramAPI.class, script, "monitor", monitor);
  }

  private static void setField(Class<?> owner, Object instance, String fieldName, Object value)
      throws Exception {
    Field field = owner.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(instance, value);
  }

  private static Object defaultReturn(Class<?> returnType) {
    if (!returnType.isPrimitive()) {
      if (returnType == String.class) return "";
      if (returnType == List.class
          || returnType == java.util.Collection.class
          || returnType == Iterable.class) {
        return List.of();
      }
      if (returnType == Set.class) return Set.of();
      if (returnType == java.util.Map.class) return java.util.Map.of();
      if (returnType == java.util.Iterator.class) return Collections.emptyIterator();
      if (returnType.isArray()) {
        return java.lang.reflect.Array.newInstance(returnType.getComponentType(), 0);
      }
      if (returnType.isInterface()) {
        return Proxy.newProxyInstance(
            returnType.getClassLoader(),
            new Class<?>[] {returnType},
            new DummyInterfaceHandler(returnType.getSimpleName()));
      }
      return null;
    }
    if (returnType == boolean.class) return false;
    if (returnType == byte.class) return (byte) 0;
    if (returnType == short.class) return (short) 0;
    if (returnType == int.class) return 0;
    if (returnType == long.class) return 0L;
    if (returnType == float.class) return 0f;
    if (returnType == double.class) return 0d;
    if (returnType == char.class) return '\0';
    return null;
  }

  private record DummyInterfaceHandler(String label) implements InvocationHandler {
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
      return switch (method.getName()) {
        case "toString" -> "Dummy(" + label + ")";
        case "hashCode" -> System.identityHashCode(proxy);
        case "equals" -> proxy == args[0];
        default -> defaultReturn(method.getReturnType());
      };
    }
  }

  private static final class FakeProgramHandler implements InvocationHandler {
    private final String name;

    FakeProgramHandler(String name) {
      this.name = name;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) {
      return switch (method.getName()) {
        case "getName" -> name;
        case "toString" -> "FakeProgram(" + name + ")";
        case "hashCode" -> System.identityHashCode(proxy);
        case "equals" -> proxy == args[0];
        default -> defaultReturn(method.getReturnType());
      };
    }
  }

  private Path buildFullRuntimeJar(Path destination) throws IOException, URISyntaxException {
    Set<Path> classEntries = new LinkedHashSet<>();
    for (Class<?> anchor :
        new Class<?>[] {
          Bootstrap.class,
          AgentConfig.class,
          AgentWebSocketServer.class,
          McpConfig.class,
          app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory.class,
          app.byteland.ghidra.service.BridgeServices.class,
          app.byteland.ghidra.api.ApiRegistry.class,
          app.byteland.ghidra.JsonUtil.class
        }) {
      URL location = anchor.getProtectionDomain().getCodeSource().getLocation();
      classEntries.add(Path.of(location.toURI()));
    }
    try (JarOutputStream jarOut = new JarOutputStream(Files.newOutputStream(destination))) {
      Set<String> added = new LinkedHashSet<>();
      for (Path entryPath : classEntries) {
        if (Files.isDirectory(entryPath)) {
          Path appDir = entryPath.resolve("app/byteland/ghidra");
          if (!Files.isDirectory(appDir)) {
            continue;
          }
          try (var walk = Files.walk(appDir)) {
            for (Path file : walk.filter(Files::isRegularFile).toList()) {
              String rel = entryPath.relativize(file).toString().replace(File.separatorChar, '/');
              if (!rel.endsWith(".class") || rel.endsWith("Test.class") || !added.add(rel)) {
                continue;
              }
              jarOut.putNextEntry(new JarEntry(rel));
              try (InputStream in = Files.newInputStream(file)) {
                in.transferTo(jarOut);
              }
              jarOut.closeEntry();
            }
          }
        } else if (Files.isRegularFile(entryPath) && entryPath.toString().endsWith(".jar")) {
          try (java.util.jar.JarFile jarFile = new java.util.jar.JarFile(entryPath.toFile())) {
            for (JarEntry jarEntry : Collections.list(jarFile.entries())) {
              String rel = jarEntry.getName();
              if (jarEntry.isDirectory()
                  || !rel.startsWith("app/byteland/ghidra/")
                  || !rel.endsWith(".class")
                  || rel.endsWith("Test.class")
                  || !added.add(rel)) {
                continue;
              }
              jarOut.putNextEntry(new JarEntry(rel));
              try (InputStream in = jarFile.getInputStream(jarEntry)) {
                in.transferTo(jarOut);
              }
              jarOut.closeEntry();
            }
          }
        }
      }
    }
    return destination;
  }

  private static String compilerClasspath() throws Exception {
    Set<Path> entries = new LinkedHashSet<>();
    for (Class<?> cls :
        new Class<?>[] {
          Class.forName("Bridge"),
          GhidraScript.class,
          FlatProgramAPI.class,
          Program.class,
          CancelledException.class,
          TaskMonitor.class
        }) {
      URL location = cls.getProtectionDomain().getCodeSource().getLocation();
      entries.add(Path.of(location.toURI()));
    }
    return entries.stream().map(Path::toString).collect(Collectors.joining(File.pathSeparator));
  }

  @FunctionalInterface
  interface PromptCallback {
    String ask(String title, String message, String defaultValue) throws CancelledException;
  }

  private HarnessClasses compileHarnessClasses() throws Exception {
    Path srcDir = tempDir.resolve("harness-src");
    Path outDir = tempDir.resolve("harness-classes");
    Files.createDirectories(srcDir);
    Files.createDirectories(outDir);

    for (String baseClass : new String[] {"Bridge", "GhidraMcp"}) {
      String subclassName = "Testable" + baseClass;
      String source =
          "import ghidra.program.model.listing.Program;\n"
              + "import ghidra.util.exception.CancelledException;\n"
              + "import java.util.List;\n"
              + "import java.util.concurrent.atomic.AtomicInteger;\n"
              + "public final class "
              + subclassName
              + " extends "
              + baseClass
              + " {\n"
              + "  public interface AskHook {\n"
              + "    String ask(String t, String m, String d) throws CancelledException;\n"
              + "  }\n"
              + "  private final boolean headless;\n"
              + "  private final AskHook hook;\n"
              + "  private final List<String> out;\n"
              + "  private final List<String> err;\n"
              + "  private final AtomicInteger prompts;\n"
              + "  public "
              + subclassName
              + "(boolean headless, Object hookObj, List<String> out, List<String> err,"
              + " AtomicInteger prompts) {\n"
              + "    this.headless = headless;\n"
              + "    this.hook = (AskHook) hookObj;\n"
              + "    this.out = out;\n"
              + "    this.err = err;\n"
              + "    this.prompts = prompts;\n"
              + "  }\n"
              + "  @Override protected boolean runningHeadless() { return headless; }\n"
              + "  @Override public String askString(String t, String m, String d)"
              + " throws CancelledException {\n"
              + "    prompts.incrementAndGet();\n"
              + "    return hook.ask(t, m, d);\n"
              + "  }\n"
              + "  @Override public void println(String s) { out.add(s); }\n"
              + "  @Override public void printerr(String s) { err.add(s); }\n"
              + "  @Override public void saveProgram(Program p) {}\n"
              + "}\n";
      Files.writeString(srcDir.resolve(subclassName + ".java"), source, StandardCharsets.UTF_8);
    }

    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    int rc =
        compiler.run(
            null,
            null,
            null,
            "-proc:none",
            "-classpath",
            compilerClasspath(),
            "-d",
            outDir.toString(),
            srcDir.resolve("TestableBridge.java").toString(),
            srcDir.resolve("TestableGhidraMcp.java").toString());
    assertEquals(0, rc, "Failed to compile launcher test subclasses");

    URLClassLoader loader =
        new URLClassLoader(new URL[] {outDir.toUri().toURL()}, getClass().getClassLoader());
    return new HarnessClasses(loader);
  }

  private record HarnessClasses(URLClassLoader loader) {
    ScriptHarness newScript(
        String baseClassName, boolean headless, String[] scriptArgs, PromptCallback callback)
        throws Exception {
      Class<?> subclass = Class.forName("Testable" + baseClassName, true, loader);
      Class<?> hookInterface = Class.forName("Testable" + baseClassName + "$AskHook", true, loader);
      Object hookProxy =
          Proxy.newProxyInstance(
              loader,
              new Class<?>[] {hookInterface},
              (proxy, method, args) ->
                  callback.ask((String) args[0], (String) args[1], (String) args[2]));
      List<String> out = new ArrayList<>();
      List<String> err = new ArrayList<>();
      java.util.concurrent.atomic.AtomicInteger prompts =
          new java.util.concurrent.atomic.AtomicInteger();
      GhidraScript instance =
          (GhidraScript)
              subclass
                  .getDeclaredConstructor(
                      boolean.class,
                      Object.class,
                      List.class,
                      List.class,
                      java.util.concurrent.atomic.AtomicInteger.class)
                  .newInstance(headless, hookProxy, out, err, prompts);
      instance.setScriptArgs(scriptArgs);
      return new ScriptHarness(Class.forName(baseClassName, true, loader), instance, out, err, prompts);
    }
  }

  private record ScriptHarness(
      Class<?> baseClass,
      GhidraScript instance,
      List<String> outputLines,
      List<String> errorLines,
      java.util.concurrent.atomic.AtomicInteger prompts) {
    int promptCount() {
      return prompts.get();
    }

    void invokeRun() throws Exception {
      Method runMethod = baseClass.getMethod("run");
      try {
        runMethod.invoke(instance);
      } catch (InvocationTargetException invocation) {
        if (invocation.getTargetException() instanceof Exception ex) {
          throw ex;
        }
        if (invocation.getTargetException() instanceof Error err) {
          throw err;
        }
        throw invocation;
      }
    }

    String[] invokeResolveStartupArgs() throws Exception {
      Method resolve = baseClass.getDeclaredMethod("resolveStartupArgs");
      resolve.setAccessible(true);
      try {
        return (String[]) resolve.invoke(instance);
      } catch (InvocationTargetException invocation) {
        if (invocation.getTargetException() instanceof Exception ex) {
          throw ex;
        }
        throw invocation;
      }
    }
  }
}
