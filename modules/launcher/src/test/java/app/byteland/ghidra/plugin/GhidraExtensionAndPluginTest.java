package app.byteland.ghidra.plugin;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.plugin.DaemonAttachDiscovery.AttachTarget;
import app.byteland.ghidra.plugin.PluginSettings.TransportMode;
import app.byteland.ghidra.service.BridgeServices;
import generic.jar.ResourceFile;
import ghidra.app.CorePluginPackage;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.exception.CancelledException;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.ZipFile;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GhidraExtensionAndPluginTest {

  private static BridgeServices dummyServices() {
    return new BridgeServices(
        proxy(app.byteland.ghidra.service.program.ProgramService.class),
        proxy(app.byteland.ghidra.service.address.AddressService.class),
        proxy(app.byteland.ghidra.service.comment.CommentService.class),
        proxy(app.byteland.ghidra.service.reference.ReferenceService.class),
        proxy(app.byteland.ghidra.service.memory.MemoryService.class),
        proxy(app.byteland.ghidra.service.listing.ListingService.class),
        proxy(app.byteland.ghidra.service.function.FunctionService.class),
        proxy(app.byteland.ghidra.service.globalvariable.GlobalVariableService.class),
        proxy(app.byteland.ghidra.service.analysis.AnalysisService.class),
        proxy(app.byteland.ghidra.service.decompilation.DecompilationService.class),
        proxy(app.byteland.ghidra.service.symbol.SymbolService.class),
        proxy(app.byteland.ghidra.service.datatype.DataTypeService.class),
        proxy(app.byteland.ghidra.service.TransactionRunner.class),
        "sample.elf");
  }

  private static <T> T proxy(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (instance, method, args) -> null));
  }

  private static Program fakeProgram(String name, String md5, String exePath) {
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (instance, method, args) ->
                switch (method.getName()) {
                  case "getName" -> name;
                  case "getExecutableMD5" -> md5;
                  case "getExecutablePath" -> exePath;
                  case "getDomainFile" -> null;
                  default -> null;
                });
  }

  @Test
  void pluginSettingsRegistersOptionsWithoutTokenAndValidatesInputs() throws Exception {
    ToolOptions options = new ToolOptions(PluginSettings.OPTIONS_CATEGORY);
    PluginSettings.registerOptions(options);

    List<String> names = options.getOptionNames();
    assertTrue(names.contains(PluginSettings.OPTION_AUTO_START));
    assertTrue(names.contains(PluginSettings.OPTION_TRANSPORT_MODE));
    assertTrue(names.contains(PluginSettings.OPTION_HOST));
    assertTrue(names.contains(PluginSettings.OPTION_PORT));
    assertTrue(names.contains(PluginSettings.OPTION_PATH));
    assertTrue(names.contains(PluginSettings.OPTION_TOOL_PREFIX));
    assertTrue(names.contains(PluginSettings.OPTION_AUTO_ATTACH_DAEMON));
    for (String optionName : names) {
      assertFalse(
          optionName.toLowerCase().contains("token"),
          "ToolOptions must never persist bearer tokens");
    }

    options.setEnum(PluginSettings.OPTION_TRANSPORT_MODE, TransportMode.WEBSOCKET_SERVER);
    options.setInt(PluginSettings.OPTION_PORT, 9876);
    options.setString(PluginSettings.OPTION_TOOL_PREFIX, "custom_mcp");
    options.setBoolean(PluginSettings.OPTION_AUTO_START, false);

    PluginSettings loaded = PluginSettings.fromOptions(options);
    assertFalse(loaded.autoStart());
    assertEquals(TransportMode.WEBSOCKET_SERVER, loaded.transportMode());
    assertEquals(9876, loaded.port());
    assertEquals("/ws/agent", loaded.path());
    assertEquals("custom_mcp", loaded.toolPrefix());

    assertThrows(
        OptionsVetoException.class,
        () -> PluginSettings.validateOptionChange(PluginSettings.OPTION_HOST, "0.0.0.0"));
    assertThrows(
        OptionsVetoException.class,
        () -> PluginSettings.validateOptionChange(PluginSettings.OPTION_PORT, 70000));
    assertThrows(
        OptionsVetoException.class,
        () ->
            PluginSettings.validateOptionChange(
                PluginSettings.OPTION_TOOL_PREFIX, "invalid.dot"));
  }

  @Test
  void daemonAttachDiscoveryReadsLoopbackTargetAndComputesSessionMd5(@TempDir Path tempDir)
      throws Exception {
    Path runDir = tempDir.resolve("ghidra-mcp-1001");
    Files.createDirectories(runDir);
    try {
      Files.setPosixFilePermissions(runDir, PosixFilePermissions.fromString("rwx------"));
    } catch (UnsupportedOperationException ignored) {
      // Non-POSIX filesystems skip permission bits.
    }
    Files.writeString(runDir.resolve("server.json"), "{\"pid\":1}", StandardCharsets.UTF_8);
    Files.writeString(
        runDir.resolve("gui-attach.json"),
        "{\"wsUrl\":\"ws://127.0.0.1:19876/ws/agent\",\"token\":\"secret-uuid\"}",
        StandardCharsets.UTF_8);

    Optional<AttachTarget> discovered =
        DaemonAttachDiscovery.discover(
            Map.of(DaemonAttachDiscovery.RUNTIME_DIR_ENV, runDir.toString()),
            "Linux",
            System.getProperty("user.name", ""),
            tempDir.toString());
    assertTrue(discovered.isPresent());
    assertEquals("ws://127.0.0.1:19876/ws/agent", discovered.get().wsUrl());
    assertEquals("secret-uuid", discovered.get().token());
    assertFalse(discovered.get().toString().contains("secret-uuid"));

    assertThrows(
        IllegalArgumentException.class,
        () -> new AttachTarget("ws://192.168.1.50:8765/ws/agent", "secret-uuid"));

    Program recorded = fakeProgram("bin", "ABCDEF0123456789ABCDEF0123456789", null);
    assertEquals(
        "abcdef0123456789abcdef0123456789",
        DaemonAttachDiscovery.computeProgramSessionId(recorded));

    Path sampleBinary = tempDir.resolve("sample.bin");
    Files.writeString(sampleBinary, "hello-ghidra", StandardCharsets.UTF_8);
    Program fromFile = fakeProgram("sample.bin", null, sampleBinary.toString());
    assertEquals(32, DaemonAttachDiscovery.computeProgramSessionId(fromFile).length());
  }

  @Test
  void backgroundRuntimeFallsBackToNextFreePortAcrossInstances() throws Exception {
    int basePort;
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress("127.0.0.1", 0));
      basePort = socket.getLocalPort();
    }

    Program program = fakeProgram("demo.elf", "0".repeat(32), null);
    AtomicReference<Program> activeRef = new AtomicReference<>(program);
    CopyOnWriteArrayList<String> statusesA = new CopyOnWriteArrayList<>();
    CopyOnWriteArrayList<String> statusesB = new CopyOnWriteArrayList<>();
    PluginSettings settings =
        new PluginSettings(
            true, TransportMode.MCP_HTTP, "127.0.0.1", basePort, "/mcp", "ghidra", false);

    try (BridgeBackgroundRuntime first =
            new BridgeBackgroundRuntime(
                dummyServices(), activeRef::get, Optional::empty, statusesA::add);
        BridgeBackgroundRuntime second =
            new BridgeBackgroundRuntime(
                dummyServices(), activeRef::get, Optional::empty, statusesB::add)) {
      first.applySettings(settings, true);
      long deadline = System.nanoTime() + java.time.Duration.ofSeconds(5).toNanos();
      while (first.localPort() == 0 && System.nanoTime() < deadline) {
        Thread.sleep(25L);
      }
      assertEquals(basePort, first.localPort());

      second.applySettings(settings, true);
      deadline = System.nanoTime() + java.time.Duration.ofSeconds(5).toNanos();
      while (second.localPort() == 0 && System.nanoTime() < deadline) {
        Thread.sleep(25L);
      }

      assertTrue(second.localPort() > first.localPort());
      assertTrue(statusesB.stream().anyMatch(text -> text.contains("MCP :" + second.localPort())));

      second.stopManual();
      deadline = System.nanoTime() + java.time.Duration.ofSeconds(5).toNanos();
      while (second.localPort() != 0 && System.nanoTime() < deadline) {
        Thread.sleep(25L);
      }
      assertEquals(0, second.localPort());
      assertTrue(statusesB.contains("Bridge: stopped"));
    }
  }

  @Test
  void launcherScriptPromptsInGuiModeAndResolvesExtensionJar(@TempDir Path tempDir)
      throws Exception {
    Path repoRoot = Path.of("").toAbsolutePath().getParent().getParent();
    Path generatedMcp =
        Path.of("build/generated/scripts/GhidraMcp.java").toAbsolutePath();
    if (!Files.isRegularFile(generatedMcp)) {
      generatedMcp =
          repoRoot.resolve("modules/launcher/build/generated/scripts/GhidraMcp.java");
    }
    assertTrue(Files.isRegularFile(generatedMcp), "Generated GhidraMcp.java must exist");

    String source = Files.readString(generatedMcp, StandardCharsets.UTF_8);
    Path testSubSource = tempDir.resolve("InteractiveGhidraMcpProbe.java");
    String probeCode =
        """
        import ghidra.util.exception.CancelledException;
        import java.io.File;

        public class InteractiveGhidraMcpProbe extends GhidraMcp {
          public String promptResponse;
          public boolean cancelPrompt;
          public String capturedTitle;
          public String capturedDefaultValue;

          @Override
          public String askString(String title, String message, String defaultValue)
              throws CancelledException {
            this.capturedTitle = title;
            this.capturedDefaultValue = defaultValue;
            if (cancelPrompt) {
              throw new CancelledException();
            }
            return promptResponse;
          }

          public String[] callResolveArgs(boolean headless) throws Exception {
            return resolveScriptArgs(headless);
          }

          public File callResolveJar(String[] args) {
            return resolveJarFile(args);
          }
        }
        """;
    Path mcpCopy = tempDir.resolve("GhidraMcp.java");
    Files.writeString(mcpCopy, source, StandardCharsets.UTF_8);
    Files.writeString(testSubSource, probeCode, StandardCharsets.UTF_8);

    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler, "System JavaCompiler is required");
    int rc =
        compiler.run(
            null,
            null,
            null,
            "-proc:none",
            "-classpath",
            System.getProperty("java.class.path"),
            mcpCopy.toString(),
            testSubSource.toString());
    assertEquals(0, rc, "Generated script and probe must compile cleanly");

    try (URLClassLoader loader =
        new URLClassLoader(
            new URL[] {tempDir.toUri().toURL()}, GhidraScript.class.getClassLoader())) {
      Class<?> probeClass = Class.forName("InteractiveGhidraMcpProbe", true, loader);
      GhidraScript instance = (GhidraScript) probeClass.getDeclaredConstructor().newInstance();
      Method callResolveArgs = probeClass.getMethod("callResolveArgs", boolean.class);
      Method callResolveJar = probeClass.getMethod("callResolveJar", String[].class);

      // GUI run without args prompts with pre-filled defaults and splits key=value pairs.
      probeClass
          .getField("promptResponse")
          .set(instance, "host=127.0.0.1 port=18766 tool_prefix=custom");
      String[] resolved = (String[]) callResolveArgs.invoke(instance, false);
      assertArrayEquals(
          new String[] {"host=127.0.0.1", "port=18766", "tool_prefix=custom"}, resolved);
      assertEquals(
          "host=127.0.0.1 port=8766 path=/mcp tool_prefix=ghidra",
          probeClass.getField("capturedDefaultValue").get(instance));

      // Prompt cancellation returns null.
      probeClass.getField("cancelPrompt").setBoolean(instance, true);
      assertNull(callResolveArgs.invoke(instance, false));

      // Headless run without args returns an empty array without a prompt.
      assertArrayEquals(new String[0], (String[]) callResolveArgs.invoke(instance, true));

      // Extension layout resolves ../lib/ghidra-bridge.jar from ghidra_scripts/GhidraMcp.java.
      Path extRoot = tempDir.resolve("ghidra-bridge");
      Path scriptsDir = Files.createDirectories(extRoot.resolve("ghidra_scripts"));
      Path libDir = Files.createDirectories(extRoot.resolve("lib"));
      Path fakeScript = Files.writeString(scriptsDir.resolve("GhidraMcp.java"), "// script");
      Path fakeJar = Files.writeString(libDir.resolve("ghidra-bridge.jar"), "jar");
      instance.setSourceFile(new ResourceFile(fakeScript.toFile()));
      File resolvedJar = (File) callResolveJar.invoke(instance, (Object) new String[0]);
      assertEquals(fakeJar.toFile().getCanonicalFile(), resolvedJar.getCanonicalFile());
    }
  }

  @Test
  void pluginMetadataAndBuiltExtensionArchiveMatchGhidraRequirements() throws Exception {
    PluginInfo info = GhidraBridgePlugin.class.getAnnotation(PluginInfo.class);
    assertNotNull(info);
    assertEquals(PluginStatus.RELEASED, info.status());
    assertEquals(CorePluginPackage.NAME, info.packageName());

    Path repoRoot = Path.of("").toAbsolutePath().getParent().getParent();
    Path zipPath = repoRoot.resolve("build/distributions/ghidra-bridge.zip");
    if (Files.isRegularFile(zipPath)) {
      try (ZipFile zip = new ZipFile(zipPath.toFile())) {
        var propsEntry = zip.getEntry("ghidra-bridge/extension.properties");
        assertNotNull(propsEntry);
        Properties props = new Properties();
        try (InputStream in = zip.getInputStream(propsEntry)) {
          props.load(in);
        }
        assertEquals("ghidra-bridge", props.getProperty("name"));
        assertFalse(props.getProperty("version", "").isBlank());
        assertNotNull(zip.getEntry("ghidra-bridge/Module.manifest"));
        assertNotNull(zip.getEntry("ghidra-bridge/lib/ghidra-bridge.jar"));
        assertNotNull(zip.getEntry("ghidra-bridge/ghidra_scripts/Bridge.java"));
        assertNotNull(zip.getEntry("ghidra-bridge/ghidra_scripts/GhidraMcp.java"));
      }
    }
  }
}
