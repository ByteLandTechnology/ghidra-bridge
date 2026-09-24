package app.byteland.ghidra;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.agent.AgentClient;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.mcp.McpHttpServer;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.program.ProgramService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * Entry point called by the generated Bridge and GhidraMcp scripts. Starts the WebSocket or MCP
 * transport.
 */
@SuppressWarnings("try")
public final class Bootstrap {
  @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
  private static final String LOOPBACK_HOST = "127.0.0.1";

  private static final String SESSION_ID_ARGUMENT = "session_id";

  private Bootstrap() {}

  public static void startFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }

    Program program = requireCurrentProgram(script);
    EffectiveConfig effectiveConfig;
    try {
      effectiveConfig = resolveConfig(args, program);
    } catch (IllegalArgumentException e) {
      printUsage(script);
      throw e;
    }
    AgentConfig config = effectiveConfig.config();
    saveCheckpoint(script, program, "[ghidra-bridge]");

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

    BridgeServices services = GhidraServiceFactory.create(script);
    try (GracefulExit gracefulExit =
        gracefulExit(services.programService(), script, "[ghidra-bridge]")) {
      try (AgentDispatcher dispatcher = new AgentDispatcher(services, config)) {
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

        client.connect(scriptCancelRequested(script));
        script.println("[ghidra-bridge] Bridge session ended.");
      }
    }
  }

  public static void startMcpFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }

    Program program = requireCurrentProgram(script);
    McpConfig mcpConfig;
    try {
      mcpConfig = resolveMcpConfig(args, program);
    } catch (IllegalArgumentException e) {
      printMcpUsage(script);
      throw e;
    }

    AgentConfig dispatcherConfig =
        new AgentConfig(
            null,
            mcpConfig.host(),
            mcpConfig.port(),
            mcpConfig.path(),
            mcpConfig.token(),
            mcpConfig.sessionId());

    saveCheckpoint(script, program, "[ghidra-mcp]");

    script.println("[ghidra-mcp] Starting MCP HTTP service");
    script.println("[ghidra-mcp]   Program: " + program.getName());
    script.println("[ghidra-mcp]   Endpoint: " + mcpConfig.endpoint());
    script.println(
        "[ghidra-mcp]   Auth Token: " + (mcpConfig.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-mcp]   Session ID: " + mcpConfig.sessionId());

    BridgeServices services = GhidraServiceFactory.create(script);
    try (GracefulExit gracefulExit =
        gracefulExit(services.programService(), script, "[ghidra-mcp]")) {
      try (AgentDispatcher dispatcher = new AgentDispatcher(services, dispatcherConfig);
          McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher, script::println)) {
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

  private static Program requireCurrentProgram(GhidraScript script) {
    Program program = script.getCurrentProgram();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
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
            + " session_id=<current-program-name>");
    script.printerr(
        "[ghidra-mcp] Example: host="
            + LOOPBACK_HOST
            + " port=8766 path=/mcp session_id=demo-session"
            + " token=secret");
  }

  private static EffectiveConfig resolveConfig(String[] args, Program program) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(AgentConfig.parseArgs(args));
    List<String> defaultMessages = new ArrayList<>();

    if (isBlank(parsedArgs.get("ws_url")) && isBlank(parsedArgs.get("port"))) {
      if (isBlank(parsedArgs.get("host"))) {
        parsedArgs.put("host", LOOPBACK_HOST);
        defaultMessages.add("host=" + LOOPBACK_HOST);
      }
      parsedArgs.put("port", "8765");
      defaultMessages.add("port=8765 (embedded server mode)");
    }

    if (isBlank(parsedArgs.get(SESSION_ID_ARGUMENT))) {
      String defaultSessionId = defaultSessionId(program);
      parsedArgs.put(SESSION_ID_ARGUMENT, defaultSessionId);
      defaultMessages.add("session_id=" + defaultSessionId);
    }

    return new EffectiveConfig(AgentConfig.fromMap(parsedArgs), defaultMessages);
  }

  private static String defaultSessionId(Program program) {
    if (program == null) {
      return "ghidra-bridge";
    }
    String name = program.getName();
    return isBlank(name) ? "ghidra-bridge" : name;
  }

  private static McpConfig resolveMcpConfig(String[] args, Program program) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(AgentConfig.parseArgs(args));
    if (isBlank(parsedArgs.get(SESSION_ID_ARGUMENT))) {
      parsedArgs.put(SESSION_ID_ARGUMENT, defaultSessionId(program));
    }
    return McpConfig.fromMap(parsedArgs);
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  record EffectiveConfig(AgentConfig config, List<String> defaultMessages) {
    EffectiveConfig {
      defaultMessages = List.copyOf(defaultMessages);
    }
  }
}
