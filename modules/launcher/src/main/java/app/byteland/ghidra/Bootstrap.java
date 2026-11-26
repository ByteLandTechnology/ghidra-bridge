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
import java.net.BindException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Function;

/**
 * The generated Bridge and GhidraMcp scripts call this entry point.
 * It starts the WebSocket or MCP transport.
 */
@SuppressWarnings("try")
public final class Bootstrap {
  static final int DEFAULT_WS_PORT = 8765;
  static final int MAX_GUI_PORT_ATTEMPTS = 64;
  private static final String LOOPBACK_HOST = "127.0.0.1";
  private static final String SESSION_ID_ARGUMENT = "session_id";
  private static final String TOOL_PREFIX_ARGUMENT = "tool_prefix";
  private static final String BANNER_DIVIDER =
      "============================================================";

  private Bootstrap() {}

  public static void startFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    startFromScript(script, args, onShutdown, GhidraServiceFactory::create, DEFAULT_WS_PORT);
  }

  static void startFromScript(
      GhidraScript script,
      String[] args,
      Runnable onShutdown,
      Function<GhidraScript, BridgeServices> serviceFactory,
      int defaultPort)
      throws Exception {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }

    Program program = requireCurrentProgram(script);
    boolean headless = script.isRunningHeadless();
    Map<String, String> rawArgs;
    EffectiveConfig initialConfig;
    try {
      rawArgs = AgentConfig.parseArgs(args);
      initialConfig = resolveWsConfig(rawArgs, program, defaultPort, false);
    } catch (IllegalArgumentException e) {
      printUsage(script);
      throw e;
    }

    boolean autoPortFallback =
        !headless
            && isBlank(rawArgs.get("ws_url"))
            && isBlank(rawArgs.get("port"))
            && isDefaultLoopbackHost(rawArgs.get("host"));
    BooleanSupplier cancelRequested = scriptCancelRequested(script);

    BridgeServices services = serviceFactory.apply(script);
    if (initialConfig.config().isOutboundMode()) {
      runOutboundSession(
          script, program, initialConfig, services, onShutdown, cancelRequested, headless);
      return;
    }

    runEmbeddedWsSession(
        script,
        program,
        rawArgs,
        initialConfig,
        services,
        onShutdown,
        cancelRequested,
        headless,
        autoPortFallback,
        defaultPort);
  }

  public static void startMcpFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    startMcpFromScript(
        script, args, onShutdown, GhidraServiceFactory::create, McpConfig.DEFAULT_PORT);
  }

  static void startMcpFromScript(
      GhidraScript script,
      String[] args,
      Runnable onShutdown,
      Function<GhidraScript, BridgeServices> serviceFactory,
      int defaultPort)
      throws Exception {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }

    Program program = requireCurrentProgram(script);
    boolean headless = script.isRunningHeadless();
    Map<String, String> rawArgs;
    McpConfig initialConfig;
    try {
      rawArgs = AgentConfig.parseArgs(args);
      initialConfig = resolveMcpConfig(rawArgs, program, defaultPort, false);
    } catch (IllegalArgumentException e) {
      printMcpUsage(script);
      throw e;
    }

    boolean autoPortFallback =
        !headless
            && isBlank(rawArgs.get("port"))
            && isDefaultLoopbackHost(rawArgs.get("host"));
    int maxAttempts = autoPortFallback ? MAX_GUI_PORT_ATTEMPTS : 1;

    BridgeServices services = serviceFactory.apply(script);
    McpConfig boundConfig = null;
    AgentDispatcher boundDispatcher = null;
    McpHttpServer boundServer = null;
    boolean usedFallback = false;

    try {
      for (int offset = 0; offset < maxAttempts; offset++) {
        int candidatePort = defaultPort + offset;
        McpConfig candidateConfig =
            offset == 0
                ? initialConfig
                : resolveMcpConfig(rawArgs, program, candidatePort, true);
        AgentDispatcher dispatcher = new AgentDispatcher(services, candidateConfig.sessionId());
        McpHttpServer server = null;
        try {
          server = new McpHttpServer(candidateConfig, dispatcher, script::println);
          boundConfig = candidateConfig;
          boundDispatcher = dispatcher;
          boundServer = server;
          usedFallback = offset > 0;
          break;
        } catch (BindException bindFailure) {
          if (server != null) {
            server.close();
          }
          boolean canRetry = offset + 1 < maxAttempts && candidatePort < 65535;
          if (!canRetry) {
            throw bindFailure;
          }
        } catch (Exception | Error failure) {
          if (server != null) {
            server.close();
          }
          throw failure;
        }
      }
      script.println("[ghidra-mcp] Starting MCP HTTP service");
      if (usedFallback) {
        script.println(
            "[ghidra-mcp] Default port "
                + defaultPort
                + " is busy; bound fallback port "
                + boundConfig.port()
                + ".");
      }
      printMcpBanner(script, program, boundConfig);
      if (headless) {
        AgentDispatcher checkpointDispatcher = boundDispatcher;
        checkpointDispatcher.runExclusive(() -> saveCheckpoint(script, program, "[ghidra-mcp]"));
      }
      boundServer.start();
      script.println("[ghidra-mcp] MCP endpoint is listening for HTTP clients.");
    } catch (Exception | Error startupFailure) {
      try {
        if (boundServer != null) {
          boundServer.close();
        }
      } finally {
        if (boundDispatcher != null) {
          boundDispatcher.close();
        } else {
          services.close();
        }
      }
      throw startupFailure;
    }
    try (GracefulExit gracefulExit =
            gracefulExit(services.programService(), program, script, "[ghidra-mcp]", headless);
        AgentDispatcher activeDispatcher = boundDispatcher;
        McpHttpServer activeServer = boundServer) {
      if (onShutdown != null) {
        gracefulExit.installShutdownHook(activeServer::close, onShutdown);
      }

      boolean stoppedBySession = false;
      boolean interrupted = false;
      try {
        stoppedBySession = activeServer.awaitShutdown(scriptCancelRequested(script));
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

  private static void runOutboundSession(
      GhidraScript script,
      Program program,
      EffectiveConfig effectiveConfig,
      BridgeServices services,
      Runnable onShutdown,
      BooleanSupplier cancelRequested,
      boolean headless)
      throws Exception {
    AgentConfig config = effectiveConfig.config();
    script.println("[ghidra-bridge] Starting bridge service");
    script.println("[ghidra-bridge]   Program: " + program.getName());
    for (String defaultMessage : effectiveConfig.defaultMessages()) {
      script.println("[ghidra-bridge]   Default: " + defaultMessage);
    }
    script.println("[ghidra-bridge]   Mode: outbound WebSocket client");
    script.println("[ghidra-bridge]   WebSocket URL: " + config.redactedWsUrl());
    script.println(
        "[ghidra-bridge]   Auth Token: " + (config.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-bridge]   Session ID: " + config.sessionId());
    script.println("[ghidra-bridge] Connecting to remote bridge...");

    AgentDispatcher dispatcher = new AgentDispatcher(services, config);
    AgentClient client =
        new AgentClient(
            config,
            dispatcher,
            new AgentClient.LifecycleListener() {
              @Override
              public void onConnected() {
                script.println("[ghidra-bridge] Outbound bridge connected to remote endpoint.");
              }
            });

    AgentClient.ActiveSession session;
    try {
      session = client.openSession(cancelRequested);
    } catch (Exception | Error connectFailure) {
      services.close();
      throw connectFailure;
    }

    if (session == null) {
      dispatcher.close();
      script.println("[ghidra-bridge] Bridge session ended.");
      return;
    }

    printWsBanner(script, program, config, config.redactedWsUrl());
    if (headless) {
      dispatcher.runExclusive(() -> saveCheckpoint(script, program, "[ghidra-bridge]"));
    }

    try (GracefulExit gracefulExit =
            gracefulExit(services.programService(), program, script, "[ghidra-bridge]", headless);
        AgentDispatcher activeDispatcher = dispatcher;
        AgentClient.ActiveSession activeSession = session) {
      if (onShutdown != null) {
        gracefulExit.installShutdownHook(client::disconnect, onShutdown);
      }

      try {
        activeSession.awaitDisconnect();
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

  private static void runEmbeddedWsSession(
      GhidraScript script,
      Program program,
      Map<String, String> rawArgs,
      EffectiveConfig initialConfig,
      BridgeServices services,
      Runnable onShutdown,
      BooleanSupplier cancelRequested,
      boolean headless,
      boolean autoPortFallback,
      int defaultPort)
      throws Exception {
    int maxAttempts = autoPortFallback ? MAX_GUI_PORT_ATTEMPTS : 1;
    EffectiveConfig boundEffective = null;
    AgentDispatcher boundDispatcher = null;
    AgentClient boundClient = null;
    AgentClient.ActiveSession boundSession = null;
    boolean usedFallback = false;

    try {
      for (int offset = 0; offset < maxAttempts; offset++) {
        int candidatePort = defaultPort + offset;
        EffectiveConfig candidate =
            offset == 0
                ? initialConfig
                : resolveWsConfig(rawArgs, program, candidatePort, true);
        AgentDispatcher dispatcher = new AgentDispatcher(services, candidate.config());
        AgentClient client = new AgentClient(candidate.config(), dispatcher);
        try {
          AgentClient.ActiveSession session = client.openSession(cancelRequested);
          boundEffective = candidate;
          boundDispatcher = dispatcher;
          boundClient = client;
          boundSession = session;
          usedFallback = offset > 0;
          break;
        } catch (BindException bindFailure) {
          boolean canRetry = offset + 1 < maxAttempts && candidatePort < 65535;
          if (!canRetry) {
            throw bindFailure;
          }
        }
      }
    } catch (Exception | Error startupFailure) {
      services.close();
      throw startupFailure;
    }

    AgentConfig config = boundEffective.config();
    script.println("[ghidra-bridge] Starting bridge service");
    for (String defaultMessage : boundEffective.defaultMessages()) {
      script.println("[ghidra-bridge]   Default: " + defaultMessage);
    }
    if (usedFallback) {
      script.println(
          "[ghidra-bridge] Default port "
              + defaultPort
              + " is busy; bound fallback port "
              + config.port()
              + ".");
    }
    printWsBanner(script, program, config, config.serverEndpoint());
    if (headless) {
      AgentDispatcher checkpointDispatcher = boundDispatcher;
      checkpointDispatcher.runExclusive(() -> saveCheckpoint(script, program, "[ghidra-bridge]"));
    }
    script.println("[ghidra-bridge] Embedded bridge is listening for WebSocket clients.");

    try (GracefulExit gracefulExit =
            gracefulExit(services.programService(), program, script, "[ghidra-bridge]", headless);
        AgentDispatcher activeDispatcher = boundDispatcher;
        AgentClient.ActiveSession activeSession = boundSession) {
      if (onShutdown != null) {
        gracefulExit.installShutdownHook(boundClient::disconnect, onShutdown);
      }

      activeSession.awaitDisconnect();
      script.println("[ghidra-bridge] Bridge session ended.");
    }
  }

  private static void printWsBanner(
      GhidraScript script, Program program, AgentConfig config, String endpointUrl) {
    script.println("[ghidra-bridge] " + BANNER_DIVIDER);
    script.println("[ghidra-bridge] WebSocket endpoint ready");
    script.println("[ghidra-bridge]   Program: " + program.getName());
    script.println("[ghidra-bridge]   Endpoint URL: " + endpointUrl);
    script.println("[ghidra-bridge]   session_id: " + config.sessionId());
    script.println("[ghidra-bridge]   tool_prefix: none (WebSocket JSON-RPC)");
    script.println(
        "[ghidra-bridge]   Auth Token: " + (config.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-bridge] " + BANNER_DIVIDER);
  }

  private static void printMcpBanner(GhidraScript script, Program program, McpConfig mcpConfig) {
    script.println("[ghidra-mcp] " + BANNER_DIVIDER);
    script.println("[ghidra-mcp] MCP HTTP endpoint ready");
    script.println("[ghidra-mcp]   Program: " + program.getName());
    script.println("[ghidra-mcp]   Endpoint URL: " + mcpConfig.endpoint());
    script.println("[ghidra-mcp]   session_id: " + mcpConfig.sessionId());
    script.println("[ghidra-mcp]   tool_prefix: " + mcpConfig.toolPrefix());
    script.println(
        "[ghidra-mcp]   Auth Token: " + (mcpConfig.token() == null ? "disabled" : "configured"));
    script.println(
        "[ghidra-mcp]   Allowed Origins: " + formatAllowedOrigins(mcpConfig.allowedOrigins()));
    script.println("[ghidra-mcp] " + BANNER_DIVIDER);
  }

  private static GracefulExit gracefulExit(
      ProgramService programService,
      Program program,
      GhidraScript script,
      String prefix,
      boolean headless) {
    if (!headless) {
      return GracefulExit.disabled();
    }
    return new GracefulExit(
        () -> {
          if (!program.isChanged()) {
            return false;
          }
          programService.saveProgram();
          return true;
        },
        () -> script.println(prefix + " Program save on exit completed."),
        failure ->
            script.printerr(prefix + " Program save on exit failed: " + errorMessage(failure)));
  }

  private static void saveCheckpoint(GhidraScript script, Program program, String prefix) {
    if (!program.isChanged()) {
      return;
    }
    try {
      script.saveProgram(program);
      script.println(prefix + " Program save checkpoint completed.");
    } catch (Exception failure) {
      script.println(prefix + " Program save checkpoint skipped: " + failure.getMessage());
    } finally {
      endScriptTransaction(script);
    }
  }

  private static void endScriptTransaction(GhidraScript script) {
    try {
      script.end(true);
    } catch (Exception ignored) {
      // No ambient script transaction is active.
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

  static EffectiveConfig resolveWsConfig(
      Map<String, String> rawArgs, Program program, int candidatePort, boolean fallback) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(rawArgs);
    List<String> defaultMessages = new ArrayList<>();

    if (isBlank(parsedArgs.get("ws_url")) && isBlank(parsedArgs.get("port"))) {
      if (isBlank(parsedArgs.get("host"))) {
        parsedArgs.put("host", LOOPBACK_HOST);
        defaultMessages.add("host=" + LOOPBACK_HOST);
      }
      String portText = Integer.toString(candidatePort);
      parsedArgs.put("port", portText);
      defaultMessages.add("port=" + portText + " (embedded server mode)");
    }

    if (isBlank(parsedArgs.get(SESSION_ID_ARGUMENT))) {
      String sessionId =
          fallback
              ? McpConfig.deriveFallbackSessionId(programNameOrNull(program), candidatePort)
              : defaultSessionId(program);
      parsedArgs.put(SESSION_ID_ARGUMENT, sessionId);
      defaultMessages.add("session_id=" + sessionId);
    }

    return new EffectiveConfig(AgentConfig.fromMap(parsedArgs), defaultMessages);
  }

  static McpConfig resolveMcpConfig(
      Map<String, String> rawArgs, Program program, int candidatePort, boolean fallback) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(rawArgs);
    if (isBlank(parsedArgs.get("host"))) {
      parsedArgs.put("host", LOOPBACK_HOST);
    }
    if (isBlank(parsedArgs.get("port"))) {
      parsedArgs.put("port", Integer.toString(candidatePort));
    }
    if (isBlank(parsedArgs.get(SESSION_ID_ARGUMENT))) {
      parsedArgs.put(
          SESSION_ID_ARGUMENT,
          fallback
              ? McpConfig.deriveFallbackSessionId(programNameOrNull(program), candidatePort)
              : defaultSessionId(program));
    }
    if (fallback && isBlank(parsedArgs.get(TOOL_PREFIX_ARGUMENT))) {
      parsedArgs.put(
          TOOL_PREFIX_ARGUMENT,
          McpConfig.deriveFallbackToolPrefix(programNameOrNull(program), candidatePort));
    }
    return McpConfig.fromMap(parsedArgs);
  }

  private static String programNameOrNull(Program program) {
    return program == null ? null : program.getName();
  }

  private static String defaultSessionId(Program program) {
    String name = programNameOrNull(program);
    return isBlank(name) ? "ghidra-bridge" : name;
  }

  static McpConfig resolveMcpConfig(String[] args, Program program) {
    return resolveMcpConfig(
        AgentConfig.parseArgs(args), program, McpConfig.DEFAULT_PORT, false);
  }

  private static boolean isDefaultLoopbackHost(String host) {
    return isBlank(host) || LOOPBACK_HOST.equals(host.trim());
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
