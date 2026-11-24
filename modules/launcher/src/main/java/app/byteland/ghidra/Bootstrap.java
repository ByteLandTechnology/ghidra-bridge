package app.byteland.ghidra;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.agent.AgentClient;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.mcp.McpHttpServer;
import app.byteland.ghidra.network.NetworkBinding;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.program.ProgramService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * The generated Bridge and GhidraMcp scripts call this entry point.
 * It starts the WebSocket or MCP transport.
 */
@SuppressWarnings("try")
public final class Bootstrap {
  @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
  private static final String LOOPBACK_HOST = "127.0.0.1";

  private static final String BRIDGE_PREFIX = "[ghidra-bridge]";
  private static final String MCP_PREFIX = "[ghidra-mcp]";
  private static final String SESSION_ID_ARGUMENT = "session_id";

  @FunctionalInterface
  private interface SessionRunner {
    void run(BridgeServices services, GracefulExit gracefulExit) throws Exception;
  }

  private Bootstrap() {}

  public static void startFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    Program program = requireScriptProgram(script);
    EffectiveConfig effectiveConfig =
        resolveOrPrintUsage(script, () -> resolveConfig(args, program), Bootstrap::printUsage);
    AgentConfig config = effectiveConfig.config();

    runWithGracefulExit(
        script,
        program,
        BRIDGE_PREFIX,
        () -> logBridgeStartup(script, program, effectiveConfig),
        (services, gracefulExit) -> {
          try (AgentDispatcher dispatcher = new AgentDispatcher(services, config.sessionId())) {
            runBridgeSession(script, config, dispatcher, gracefulExit, onShutdown);
          }
        });
  }

  public static void startMcpFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    Program program = requireScriptProgram(script);
    McpConfig mcpConfig =
        resolveOrPrintUsage(
            script, () -> resolveMcpConfig(args, program), Bootstrap::printMcpUsage);

    runWithGracefulExit(
        script,
        program,
        MCP_PREFIX,
        () -> logMcpStartup(script, program, mcpConfig),
        (services, gracefulExit) -> {
          try (AgentDispatcher dispatcher = new AgentDispatcher(services, mcpConfig.sessionId());
              McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher, script::println)) {
            runMcpSession(script, server, gracefulExit, onShutdown);
          }
        });
  }

  private static Program requireScriptProgram(GhidraScript script) {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }
    Program program = script.getCurrentProgram();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  private static <T> T resolveOrPrintUsage(
      GhidraScript script, Supplier<T> resolver, Consumer<GhidraScript> usagePrinter) {
    try {
      return resolver.get();
    } catch (IllegalArgumentException error) {
      usagePrinter.accept(script);
      throw error;
    }
  }

  private static void runWithGracefulExit(
      GhidraScript script,
      Program program,
      String prefix,
      Runnable startupLogger,
      SessionRunner sessionRunner)
      throws Exception {
    saveCheckpoint(script, program, prefix);
    startupLogger.run();
    BridgeServices services = GhidraServiceFactory.create(script);
    try (GracefulExit gracefulExit = gracefulExit(services.programService(), script, prefix)) {
      sessionRunner.run(services, gracefulExit);
    }
  }

  private static void logBridgeStartup(
      GhidraScript script, Program program, EffectiveConfig effectiveConfig) {
    AgentConfig config = effectiveConfig.config();
    script.println("[ghidra-bridge] Starting bridge service");
    script.println("[ghidra-bridge]   Program: " + program.getName());
    for (String defaultMessage : effectiveConfig.defaultMessages()) {
      script.println("[ghidra-bridge]   Default: " + defaultMessage);
    }
    if (config.isOutboundMode()) {
      script.println("[ghidra-bridge]   Mode: outbound WebSocket client");
      script.println("[ghidra-bridge]   WebSocket URL: " + config.redactedWsUrl());
      script.println(
          "[ghidra-bridge]   Auth Token: " + (config.token() == null ? "disabled" : "configured"));
      script.println("[ghidra-bridge] Connecting to remote bridge...");
    } else {
      script.println("[ghidra-bridge]   Mode: embedded WebSocket server");
      script.println(
          "[ghidra-bridge]   Listen Address: ws://"
              + config.host()
              + ":"
              + config.port()
              + config.path());
      script.println(
          "[ghidra-bridge]   Auth Token: " + (config.token() == null ? "disabled" : "configured"));
      script.println("[ghidra-bridge] Starting embedded bridge listener...");
    }
    script.println("[ghidra-bridge]   Session ID: " + config.sessionId());
  }

  private static void runBridgeSession(
      GhidraScript script,
      AgentConfig config,
      AgentDispatcher dispatcher,
      GracefulExit gracefulExit,
      Runnable onShutdown)
      throws Exception {
    AgentClient client =
        new AgentClient(
            config,
            dispatcher,
            new AgentClient.LifecycleListener() {
              @Override
              public void onListening() {
                script.println(
                    "[ghidra-bridge] Embedded bridge is listening for WebSocket clients.");
              }

              @Override
              public void onConnected() {
                script.println("[ghidra-bridge] Outbound bridge connected to remote endpoint.");
              }
            });

    if (onShutdown != null) {
      gracefulExit.installShutdownHook(client::disconnect, onShutdown);
    }

    try {
      client.connect(scriptCancelRequested(script));
    } finally {
      // Start the deadline for all session end conditions.
      // The close, the save, and the exit follow.
      if (config.exitDeadlineSeconds() != null) {
        gracefulExit.startExitDeadline(
            Duration.ofSeconds(config.exitDeadlineSeconds()), script::printerr);
      }
    }
    script.println("[ghidra-bridge] Bridge session ended.");
  }

  private static void logMcpStartup(GhidraScript script, Program program, McpConfig mcpConfig) {
    script.println("[ghidra-mcp] Starting MCP HTTP service");
    script.println("[ghidra-mcp]   Program: " + program.getName());
    script.println("[ghidra-mcp]   Endpoint: " + mcpConfig.endpoint());
    script.println(
        "[ghidra-mcp]   Auth Token: " + (mcpConfig.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-mcp]   Session ID: " + mcpConfig.sessionId());
    script.println("[ghidra-mcp]   Tool Prefix: " + mcpConfig.toolPrefix());
  }

  private static void runMcpSession(
      GhidraScript script, McpHttpServer server, GracefulExit gracefulExit, Runnable onShutdown) {
    if (onShutdown != null) {
      gracefulExit.installShutdownHook(server::close, onShutdown);
    }

    server.start();
    script.println("[ghidra-mcp] MCP endpoint is listening for HTTP clients.");
    boolean stoppedBySession = false;
    boolean interrupted = false;
    try {
      stoppedBySession = server.awaitShutdown(scriptCancelRequested(script));
    } catch (InterruptedException interruptedException) {
      interrupted = true;
      script.println("[ghidra-mcp] Stop requested; shutting down MCP HTTP service.");
    }
    if (!stoppedBySession && !interrupted) {
      script.println("[ghidra-mcp] Stop requested; shutting down MCP HTTP service.");
    }
    script.println("[ghidra-mcp] MCP session ended.");
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static GracefulExit gracefulExit(
      ProgramService programService, GhidraScript script, String prefix) {
    return new GracefulExit(
        programService::saveProgram,
        () -> script.println(prefix + " Program save on exit completed."),
        failure ->
            script.printerr(prefix + " Program save on exit failed: " + errorMessage(failure)));
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void saveCheckpoint(GhidraScript script, Program program, String prefix) {
    try {
      script.saveProgram(program);
      script.println(prefix + " Program save checkpoint completed.");
    } catch (Exception failure) {
      script.println(prefix + " Program save checkpoint skipped: " + failure.getMessage());
    }
  }

  private static String errorMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? failure.getClass().getName() : message;
  }

  private static BooleanSupplier scriptCancelRequested(GhidraScript script) {
    return () -> script.getMonitor() != null && script.getMonitor().isCancelled();
  }

  private static void printUsage(GhidraScript script) {
    script.printerr("[ghidra-bridge] Invalid startup arguments.");
    script.printerr(
        "[ghidra-bridge] Defaults are used when ws_url, port, and session_id are omitted.");
    script.printerr(
        "[ghidra-bridge] If you configure transport manually, use ws_url or host/port/path.");
    script.printerr(
        "[ghidra-bridge] Example (embedded): port=8765 host="
            + LOOPBACK_HOST
            + " path=/ws/agent"
            + " session_id=demo-session token=secret");
    script.printerr(
        "[ghidra-bridge] Example (outbound): ws_url=ws://"
            + LOOPBACK_HOST
            + ":8765/ws/agent"
            + " session_id=demo-session token=secret");
  }

  private static void printMcpUsage(GhidraScript script) {
    script.printerr("[ghidra-mcp] Invalid startup arguments.");
    script.printerr(
        "[ghidra-mcp] Defaults: host="
            + LOOPBACK_HOST
            + " port=8766 path=/mcp"
            + " session_id=<current-program-name> tool_prefix=ghidra");
    script.printerr(
        "[ghidra-mcp] Example: host="
            + LOOPBACK_HOST
            + " port=8766 path=/mcp session_id=demo-session"
            + " token=secret");
  }

  private static EffectiveConfig resolveConfig(String[] args, Program program) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(NetworkBinding.parseArgs(args));
    List<String> defaultMessages = new ArrayList<>();

    if (NetworkBinding.optionalText(parsedArgs.get("ws_url")) == null
        && NetworkBinding.optionalText(parsedArgs.get("port")) == null) {
      if (NetworkBinding.optionalText(parsedArgs.get("host")) == null) {
        parsedArgs.put("host", LOOPBACK_HOST);
        defaultMessages.add("host=" + LOOPBACK_HOST);
      }
      parsedArgs.put("port", "8765");
      defaultMessages.add("port=8765 (embedded server mode)");
    }

    String defaultSessionId = applyDefaultSessionId(parsedArgs, program);
    if (defaultSessionId != null) {
      defaultMessages.add("session_id=" + defaultSessionId);
    }

    return new EffectiveConfig(AgentConfig.fromMap(parsedArgs), defaultMessages);
  }

  private static McpConfig resolveMcpConfig(String[] args, Program program) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(NetworkBinding.parseArgs(args));
    applyDefaultSessionId(parsedArgs, program);
    return McpConfig.fromMap(parsedArgs);
  }

  private static String applyDefaultSessionId(Map<String, String> parsedArgs, Program program) {
    if (NetworkBinding.optionalText(parsedArgs.get(SESSION_ID_ARGUMENT)) != null) {
      return null;
    }
    String sessionId = defaultSessionId(program);
    parsedArgs.put(SESSION_ID_ARGUMENT, sessionId);
    return sessionId;
  }

  private static String defaultSessionId(Program program) {
    return NetworkBinding.defaultSessionId(program == null ? null : program.getName());
  }

  record EffectiveConfig(AgentConfig config, List<String> defaultMessages) {
    EffectiveConfig {
      defaultMessages = List.copyOf(defaultMessages);
    }
  }
}
