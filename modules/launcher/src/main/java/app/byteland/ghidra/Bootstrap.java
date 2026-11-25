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
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import java.io.Console;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * The generated Bridge and GhidraMcp scripts call this entry point.
 * It starts the WebSocket or MCP transport.
 */
@SuppressWarnings("try")
public final class Bootstrap {
  private static final String LOOPBACK_HOST = "127.0.0.1";

  private static final String SESSION_ID_ARGUMENT = "session_id";
  private static final String TOKEN_ARGUMENT = "token";
  private static final int GENERATED_TOKEN_BYTES = 32;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private Bootstrap() {}

  public static void startFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }

    Program program = requireCurrentProgram(script);
    ConsoleService guiConsole = findConsoleService(script);
    Console systemConsole = System.console();
    EffectiveConfig effectiveConfig;
    try {
      effectiveConfig =
          resolveConfig(args, program, guiConsole != null || systemConsole != null);
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
      reportServerAuthToken(script, guiConsole, systemConsole, effectiveConfig.generatedToken());
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

    saveCheckpoint(script, program, "[ghidra-mcp]");

    script.println("[ghidra-mcp] Starting MCP HTTP service");
    script.println("[ghidra-mcp]   Program: " + program.getName());
    script.println("[ghidra-mcp]   Endpoint: " + mcpConfig.endpoint());
    script.println(
        "[ghidra-mcp]   Auth Token: " + (mcpConfig.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-mcp]   Session ID: " + mcpConfig.sessionId());
    script.println("[ghidra-mcp]   Tool Prefix: " + mcpConfig.toolPrefix());
    script.println(
        "[ghidra-mcp]   Allowed Origins: " + formatAllowedOrigins(mcpConfig.allowedOrigins()));

    BridgeServices services = GhidraServiceFactory.create(script);
    try (GracefulExit gracefulExit =
        gracefulExit(services.programService(), script, "[ghidra-mcp]")) {
      try (AgentDispatcher dispatcher = new AgentDispatcher(services, mcpConfig.sessionId());
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
        "[ghidra-bridge] Defaults are used when ws_url, port, token, and session_id are omitted"
            + " in an interactive console.");
    script.printerr(
        "[ghidra-bridge] Non-interactive headless server mode requires token=<secret>.");
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
            + " session_id=<current-program-name> tool_prefix=ghidra"
            + " allowed_origins=<loopback-and-host>");
    script.printerr(
        "[ghidra-mcp] Example: host="
            + LOOPBACK_HOST
            + " port=8766 path=/mcp session_id=demo-session"
            + " token=secret allowed_origins=https://inspector.example.com");
  }

  private static String formatAllowedOrigins(Set<String> allowedOrigins) {
    if (allowedOrigins == null) {
      return "loopback and host (default)";
    }
    if (allowedOrigins.isEmpty()) {
      return "none";
    }
    return String.join(", ", allowedOrigins);
  }

  static EffectiveConfig resolveConfig(String[] args, Program program) {
    return resolveConfig(args, program, true);
  }

  static EffectiveConfig resolveConfig(
      String[] args, Program program, boolean interactiveConsoleAvailable) {
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

    String generatedToken = null;
    if (isBlank(parsedArgs.get("ws_url")) && !parsedArgs.containsKey(TOKEN_ARGUMENT)) {
      if (!interactiveConsoleAvailable) {
        throw new IllegalArgumentException(
            "token is required in headless server mode when no interactive console is available;"
                + " pass token=<secret>");
      }
      generatedToken = generateSessionToken();
      parsedArgs.put(TOKEN_ARGUMENT, generatedToken);
      defaultMessages.add("token=<generated>");
    }

    return new EffectiveConfig(AgentConfig.fromMap(parsedArgs), defaultMessages, generatedToken);
  }

  static String generateSessionToken() {
    byte[] bytes = new byte[GENERATED_TOKEN_BYTES];
    SECURE_RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  static boolean reportServerAuthToken(GhidraScript script, String generatedToken) {
    return reportServerAuthToken(script, findConsoleService(script), System.console(), generatedToken);
  }

  static boolean reportServerAuthToken(
      GhidraScript script,
      ConsoleService guiConsole,
      Console systemConsole,
      String generatedToken) {
    if (generatedToken == null) {
      script.println("[ghidra-bridge]   Auth Token: configured");
      return true;
    }
    if (guiConsole != null) {
      script.println("[ghidra-bridge]   Auth Token: generated (printed to console)");
      guiConsole.println("[ghidra-bridge]   Session Token: " + generatedToken);
      return true;
    }
    if (systemConsole != null) {
      script.println("[ghidra-bridge]   Auth Token: generated (printed to console)");
      systemConsole.writer().println("[ghidra-bridge]   Session Token: " + generatedToken);
      systemConsole.flush();
      return true;
    }
    script.println(
        "[ghidra-bridge]   Auth Token: generated (no interactive console; pass token=<secret> in"
            + " headless mode)");
    return false;
  }

  private static ConsoleService findConsoleService(GhidraScript script) {
    final GhidraState state;
    try {
      state = script.getState();
    } catch (NullPointerException uninitializedState) {
      return null;
    }
    if (state == null) {
      return null;
    }
    PluginTool tool = state.getTool();
    return tool == null ? null : tool.getService(ConsoleService.class);
  }

  private static String defaultSessionId(Program program) {
    if (program == null) {
      return "ghidra-bridge";
    }
    String name = program.getName();
    return isBlank(name) ? "ghidra-bridge" : name;
  }

  static McpConfig resolveMcpConfig(String[] args, Program program) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(AgentConfig.parseArgs(args));
    if (isBlank(parsedArgs.get(SESSION_ID_ARGUMENT))) {
      parsedArgs.put(SESSION_ID_ARGUMENT, defaultSessionId(program));
    }
    return McpConfig.fromMap(parsedArgs);
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  record EffectiveConfig(
      AgentConfig config, List<String> defaultMessages, String generatedToken) {
    EffectiveConfig {
      defaultMessages = List.copyOf(defaultMessages);
    }
  }
}
