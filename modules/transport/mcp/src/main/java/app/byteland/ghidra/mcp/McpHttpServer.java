package app.byteland.ghidra.mcp;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.network.NetworkBinding;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * HTTP server that exposes the bridge API as grouped MCP tools through Streamable HTTP and SSE.
 */
public final class McpHttpServer implements AutoCloseable {
  private static final int JSONRPC_PARSE_ERROR = -32700;
  private static final int JSONRPC_INVALID_REQUEST = -32600;
  private static final int JSONRPC_METHOD_NOT_FOUND = -32601;
  private static final int JSONRPC_INVALID_PARAMS = -32602;
  private static final int JSONRPC_INTERNAL_ERROR = -32603;
  private static final int JSONRPC_UNAUTHORIZED = -32001;
  private static final int JSONRPC_RESOURCE_NOT_FOUND = -32002;
  private static final String MCP_PROTOCOL_VERSION = "2026-07-28";
  private static final String INITIALIZE_PROTOCOL_VERSION = "2025-11-25";
  private static final String JUNE_2025_PROTOCOL_VERSION = "2025-06-18";
  private static final List<String> INITIALIZE_PROTOCOL_VERSIONS =
      List.of("2024-11-05", "2025-03-26", JUNE_2025_PROTOCOL_VERSION, INITIALIZE_PROTOCOL_VERSION);
  private static final List<String> SUPPORTED_PROTOCOL_VERSIONS =
      List.of(
          MCP_PROTOCOL_VERSION,
          INITIALIZE_PROTOCOL_VERSION,
          JUNE_2025_PROTOCOL_VERSION,
          "2025-03-26",
          "2024-11-05");
  private static final int HEADER_MISMATCH = -32020;
  private static final int UNSUPPORTED_PROTOCOL_VERSION = -32022;
  private static final String MCP_TOOLS_RESOURCE_URI = "ghidra-bridge://contracts/mcp-tools";
  private static final String HTTP_GET_METHOD = "GET";
  private static final String HTTP_HEAD_METHOD = "HEAD";
  private static final String HTTP_OPTIONS_METHOD = "OPTIONS";
  private static final String HTTP_POST_METHOD = "POST";
  private static final String CONTENT_TYPE_HEADER = "Content-Type";
  private static final String PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version";
  private static final String METHOD_FIELD = "method";
  private static final String PARAMS_FIELD = "params";
  private static final String TOOLS_FIELD = "tools";
  private static final String CAPABILITIES_FIELD = "capabilities";
  private static final String OPERATION_FIELD = "operation";
  private static final String RESULT_TYPE_FIELD = "resultType";
  private static final String COMPLETE_RESULT = "complete";
  private static final String TOOLS_CALL_METHOD = "tools/call";
  private static final String RESOURCES_READ_METHOD = "resources/read";
  private static final String NAME_FIELD = "name";
  private static final String URI_FIELD = "uri";
  private static final String SESSION_ID_PARAM = "sessionId";

  private final McpConfig config;
  private final AgentDispatcher dispatcher;
  private final Consumer<String> requestLogSink;
  private final McpToolRegistry toolRegistry;
  private final String toolContractJson;
  private final HttpServer server;
  private final ExecutorService executor;
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final Map<String, SseSession> sseSessions = new ConcurrentHashMap<>();

  /**
   * Creates an MCP HTTP server that discards request log lines.
   *
   * @param config MCP server configuration
   * @param dispatcher API request dispatcher
   * @throws IOException if binding the HTTP server socket fails
   */
  public McpHttpServer(McpConfig config, AgentDispatcher dispatcher) throws IOException {
    this(config, dispatcher, McpHttpServer::discardRequestLog);
  }

  /**
   * Creates an MCP HTTP server that writes request log lines to {@code requestLogSink}.
   *
   * @param config MCP server configuration
   * @param dispatcher API request dispatcher
   * @param requestLogSink consumer for formatted request log lines
   * @throws IOException if binding the HTTP server socket fails
   */
  public McpHttpServer(
      McpConfig config, AgentDispatcher dispatcher, Consumer<String> requestLogSink)
      throws IOException {
    this.config = Objects.requireNonNull(config, "config");
    this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    this.requestLogSink = Objects.requireNonNull(requestLogSink, "requestLogSink");
    this.toolRegistry = new McpToolRegistry(dispatcher.methodCatalog(), config.toolPrefix());
    Map<String, Object> toolContract = new LinkedHashMap<>();
    toolContract.put("protocol_version", MCP_PROTOCOL_VERSION);
    toolContract.put(TOOLS_FIELD, toolRegistry.listTools());
    this.toolContractJson = JsonUtil.toJson(toolContract);
    this.server = createServer(config);
    this.executor = Executors.newCachedThreadPool();
    this.server.setExecutor(executor);
    this.server.createContext(config.path(), new JsonRpcHandler());
  }

  private static HttpServer createServer(McpConfig config) throws IOException {
    try {
      return HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    } catch (BindException error) {
      BindException friendly =
          new BindException(
              "MCP endpoint "
                  + config.endpoint()
                  + " is already in use. Stop the existing Bridge/GhidraMcp script, close the old"
                  + " Ghidra session, or pass a different port value.");
      friendly.addSuppressed(error);
      throw friendly;
    }
  }

  /** Starts accepting HTTP connections on the bound endpoint. */
  public void start() {
    server.start();
  }

  /**
   * Waits until this server closes.
   *
   * @throws InterruptedException if the current thread is interrupted while waiting
   */
  public void awaitShutdown() throws InterruptedException {
    shutdownLatch.await();
  }

  /**
   * Waits until this server closes or {@code cancelRequested} returns {@code true}.
   *
   * @param cancelRequested supplier polled to detect external cancellation
   * @return {@code true} if closed by session shutdown, or {@code false} if canceled
   * @throws InterruptedException if the current thread is interrupted while waiting
   */
  public boolean awaitShutdown(BooleanSupplier cancelRequested) throws InterruptedException {
    return awaitShutdown(shutdownLatch, cancelRequested, this::close, 250L);
  }

  /**
   * Returns the bound HTTP endpoint URL.
   *
   * @return HTTP endpoint URL
   */
  public String endpoint() {
    return config.endpoint();
  }

  @Override
  @SuppressWarnings("PMD.CloseResource")
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    server.stop(0);
    for (SseSession session : sseSessions.values()) {
      session.close();
    }
    sseSessions.clear();
    ExecutorShutdown.shutdownAndAwait(executor);
    shutdownLatch.countDown();
  }

  static boolean awaitShutdown(
      CountDownLatch latch, BooleanSupplier cancelRequested, Runnable closeAction, long pollMillis)
      throws InterruptedException {
    Objects.requireNonNull(latch, "latch");
    Objects.requireNonNull(cancelRequested, "cancelRequested");
    Objects.requireNonNull(closeAction, "closeAction");
    try {
      while (true) {
        if (latch.await(pollMillis, TimeUnit.MILLISECONDS)) {
          return true;
        }
        if (cancelRequested.getAsBoolean()) {
          closeAction.run();
          return false;
        }
      }
    } catch (InterruptedException interrupted) {
      closeAction.run();
      throw interrupted;
    }
  }

  private final class JsonRpcHandler implements HttpHandler {
    @Override
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CloseResource"})
    public void handle(HttpExchange exchange) throws IOException {
      RequestLog log = new RequestLog(requestLogSink);
      try (exchange) {
        try {
          addCommonHeaders(exchange);
          if (!isAllowedOrigin(exchange)) {
            log.method(exchange.getRequestMethod()).error().status(403);
            writePlain(exchange, 403, "Forbidden origin");
            return;
          }

          String requestMethod = exchange.getRequestMethod();
          if (HTTP_OPTIONS_METHOD.equalsIgnoreCase(requestMethod)) {
            log.method(HTTP_OPTIONS_METHOD).ok().status(204);
            sendNoBody(exchange, 204);
            return;
          }
          if (HTTP_HEAD_METHOD.equalsIgnoreCase(requestMethod)) {
            log.method(HTTP_HEAD_METHOD).ok().status(200);
            sendNoBody(exchange, 200);
            return;
          }

          if (hasQueryToken(exchange.getRequestURI())) {
            log.error().status(400);
            writeJsonRpcError(
                exchange,
                400,
                null,
                JSONRPC_INVALID_REQUEST,
                "Query-string tokens are not supported");
            return;
          }

          if (!authorize(exchange)) {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
            log.error().status(401);
            writeJsonRpcError(exchange, 401, null, JSONRPC_UNAUTHORIZED, "Unauthorized");
            return;
          }

          if (HTTP_GET_METHOD.equalsIgnoreCase(requestMethod)) {
            handleSseGet(exchange, log);
            return;
          }

          if (!HTTP_POST_METHOD.equalsIgnoreCase(requestMethod)) {
            exchange.getResponseHeaders().set("Allow", "POST, GET, OPTIONS");
            log.method(requestMethod).error().status(405);
            writeJsonRpcError(
                exchange,
                405,
                null,
                JSONRPC_INVALID_REQUEST,
                "Only POST and GET (SSE) are supported for this MCP endpoint");
            return;
          }

          String sessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
          SseSession sseSession = null;
          if (sessionId != null) {
            sseSession = sseSessions.get(sessionId);
            if (sseSession == null || !sseSession.isActive()) {
              log.error().status(404);
              writeJsonRpcError(
                  exchange, 404, null, JSONRPC_INVALID_REQUEST, "SSE session not found or expired");
              return;
            }
          }

          if (!String.valueOf(firstHeader(exchange, CONTENT_TYPE_HEADER)).startsWith("application/json")) {
            throw new JsonRpcError(415, null, JSONRPC_INVALID_REQUEST, "Content-Type must be application/json");
          }
          Map<String, Object> request = parseRequest(readBody(exchange));
          validateJsonRpcEnvelope(request);
          boolean statelessProtocol = usesStatelessProtocol(exchange, request);
          if (statelessProtocol) {
            validateMetadata(exchange, request);
          } else {
            validateInitializeProtocol(exchange, request);
          }
          Object id = request.get("id");
          Object response = handleRequest(request, id, log, statelessProtocol);
          if (sseSession != null) {
            if (response != null) {
              sseSession.sendEvent("message", JsonUtil.toJson(response));
            }
            log.id(id).ok().status(202);
            exchange.sendResponseHeaders(202, -1);
            return;
          }
          if (response == null) {
            log.id(id).ok().status(202);
            exchange.sendResponseHeaders(202, -1);
            return;
          }
          writeJson(exchange, 200, response);
        } catch (JsonRpcError error) {
          log.error()
              .status(error.httpStatus())
              .id(error.id())
              .cause(error.httpStatus() >= 500 ? rootMessage(error) : null);
          Map<String, Object> errResponse = error.code() == UNSUPPORTED_PROTOCOL_VERSION
              ? mcpErrorResponse(exchange, error.id(), error.code(), error.getMessage(),
                  Map.of("requested", error.requestedVersion(), "supported", SUPPORTED_PROTOCOL_VERSIONS))
              : mcpErrorResponse(exchange, error.id(), error.code(), error.getMessage(), null);
          String querySessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
          SseSession activeSse = querySessionId == null ? null : sseSessions.get(querySessionId);
          if (activeSse != null && activeSse.isActive()) {
            try {
              activeSse.sendEvent("message", JsonUtil.toJson(errResponse));
            } catch (IOException ignored) {
              // Ignore stream write failure when the SSE client disconnects.
            }
            exchange.sendResponseHeaders(202, -1);
          } else {
            writeJson(exchange, error.httpStatus(), errResponse);
          }
        } catch (IOException | RuntimeException error) {
          log.error().status(500).cause(rootMessage(error));
          writeJsonRpcError(exchange, 500, null, JSONRPC_INTERNAL_ERROR, "Internal error");
        } finally {
          log.finish();
        }
      }
    }

    private void handleSseGet(HttpExchange exchange, RequestLog log) {
      String sessionId = UUID.randomUUID().toString();
      try (SseSession session = new SseSession(exchange)) {
        sseSessions.put(sessionId, session);
        log.method(HTTP_GET_METHOD).ok().status(200);
        try {
          String endpointUri = config.path() + "?" + SESSION_ID_PARAM + "=" + sessionId;
          session.sendEvent("endpoint", endpointUri);

          while (session.isActive() && !closed.get()) {
            try {
              Thread.sleep(15000L);
              session.sendComment("keepalive");
            } catch (InterruptedException interrupted) {
              Thread.currentThread().interrupt();
              break;
            }
          }
        } catch (IOException ignored) {
          // The SSE client disconnected.
        } finally {
          sseSessions.remove(sessionId);
        }
      } catch (IOException error) {
        log.method(HTTP_GET_METHOD).error().status(500);
      }
    }
  }

  private Object handleRequest(
      Map<String, Object> request, Object id, RequestLog log, boolean statelessProtocol) {
    String method = request.get(METHOD_FIELD).toString();
    log.method(method);
    if (!request.containsKey("id")) {
      return null;
    }
    Object params = request.get(PARAMS_FIELD);
    log.id(id);

    return switch (method) {
      case "initialize" -> {
        if (statelessProtocol) {
          throw new JsonRpcError(404, id, JSONRPC_METHOD_NOT_FOUND, "Method not found: " + method);
        }
        Map<String, Object> result = initializeResult(id, requireParamsMap(params, id));
        log.ok().status(200);
        yield success(id, result);
      }
      case "server/discover" -> {
        log.ok().status(200);
        yield success(id, discoveryResult());
      }
      case "ping" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol ? Map.of(RESULT_TYPE_FIELD, COMPLETE_RESULT) : Map.of());
      }
      case "tools/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of(RESULT_TYPE_FIELD, COMPLETE_RESULT, TOOLS_FIELD, toolRegistry.listTools()), true)
            : Map.of(TOOLS_FIELD, toolRegistry.listTools()));
      }
      case "resources/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of(RESULT_TYPE_FIELD, COMPLETE_RESULT, "resources", List.of(mcpToolsResource())), true)
            : Map.of("resources", List.of(mcpToolsResource())));
      }
      case "resources/templates/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of(RESULT_TYPE_FIELD, COMPLETE_RESULT, "resourceTemplates", List.of()), true)
            : Map.of("resourceTemplates", List.of()));
      }
      case RESOURCES_READ_METHOD -> {
        log.ok().status(200);
        yield success(id, cacheableResult(
            readResource(id, requireParamsMap(params, id), statelessProtocol), statelessProtocol));
      }
      case TOOLS_CALL_METHOD -> {
        yield success(id, handleToolCall(id, requireParamsMap(params, id), log, statelessProtocol));
      }
      default ->
          throw new JsonRpcError(404, id, JSONRPC_METHOD_NOT_FOUND, "Method not found: " + method);
    };
  }

  private Map<String, Object> initializeResult(Object id, Map<String, Object> params) {
    if (!(params.get("protocolVersion") instanceof String requestedVersion)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "protocolVersion must be a string");
    }
    if (!(params.get(CAPABILITIES_FIELD) instanceof Map<?, ?>)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "capabilities must be a JSON object");
    }
    validateImplementation(params.get("clientInfo"), id);
    Map<String, Object> discovery = discoveryResult();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("protocolVersion", INITIALIZE_PROTOCOL_VERSIONS.contains(requestedVersion)
        ? requestedVersion : INITIALIZE_PROTOCOL_VERSION);
    result.put(CAPABILITIES_FIELD, discovery.get(CAPABILITIES_FIELD));
    result.put("serverInfo", Map.of(NAME_FIELD, "ghidra-bridge", "version", serverVersion()));
    result.put("instructions", discovery.get("instructions"));
    return result;
  }

  private Map<String, Object> discoveryResult() {
    Map<String, Object> capabilities = new LinkedHashMap<>();
    capabilities.put(TOOLS_FIELD, Map.of("listChanged", false));
    capabilities.put("resources", Map.of("listChanged", false));

    Map<String, Object> serverInfo = new LinkedHashMap<>();
    serverInfo.put(NAME_FIELD, "ghidra-bridge");
    serverInfo.put("version", serverVersion());

    Map<String, Object> result = new LinkedHashMap<>();
    result.put(RESULT_TYPE_FIELD, COMPLETE_RESULT);
    result.put("supportedVersions", SUPPORTED_PROTOCOL_VERSIONS);
    result.put(CAPABILITIES_FIELD, capabilities);
    result.put("_meta", Map.of("io.modelcontextprotocol/serverInfo", serverInfo));
    result.put(
        "instructions",
        "Use tools/list for the current callable contract, then tools/call to interact with the"
            + " active Ghidra program. The same tool contract is readable as an MCP resource.");
    return cacheableResult(result, true);
  }

  private static Map<String, Object> cacheableResult(
      Map<String, Object> result, boolean statelessProtocol) {
    if (!statelessProtocol) return result;
    Map<String, Object> cached = new LinkedHashMap<>(result);
    cached.put("ttlMs", 0);
    cached.put("cacheScope", "private");
    return cached;
  }

  private Map<String, Object> mcpToolsResource() {
    Map<String, Object> resource = new LinkedHashMap<>();
    resource.put(URI_FIELD, MCP_TOOLS_RESOURCE_URI);
    resource.put(NAME_FIELD, "mcp-tools");
    resource.put("title", "Ghidra Bridge MCP tool contract");
    resource.put("description", "The current callable Ghidra Bridge tool catalog and schemas.");
    resource.put("mimeType", "application/json");
    return resource;
  }

  private Map<String, Object> readResource(
      Object id, Map<String, Object> params, boolean statelessProtocol) {
    String uri = requireString(params.get(URI_FIELD), URI_FIELD, id);
    if (!MCP_TOOLS_RESOURCE_URI.equals(uri)) {
      throw new JsonRpcError(statelessProtocol ? 400 : 404, id,
          statelessProtocol ? JSONRPC_INVALID_PARAMS : JSONRPC_RESOURCE_NOT_FOUND,
          "Resource not found: " + uri);
    }
    Map<String, Object> content = new LinkedHashMap<>();
    content.put(URI_FIELD, MCP_TOOLS_RESOURCE_URI);
    content.put("mimeType", "application/json");
    content.put("text", toolContractJson);
    return statelessProtocol
        ? Map.of(RESULT_TYPE_FIELD, COMPLETE_RESULT, "contents", List.of(content))
        : Map.of("contents", List.of(content));
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private Map<String, Object> handleToolCall(
      Object id, Map<String, Object> params, RequestLog log, boolean statelessProtocol) {
    String name = requireString(params.get(NAME_FIELD), NAME_FIELD, id);
    log.tool(name);
    if (!toolRegistry.hasTool(name)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + name);
    }
    Map<String, Object> arguments = requireArguments(params.get("arguments"), id);
    try {
      if (toolRegistry.isHelpTool(name)) {
        log.ok().status(200);
        return toolResult(toolRegistry.help(arguments), false, statelessProtocol);
      }
      if (!List.of(OPERATION_FIELD, PARAMS_FIELD).containsAll(arguments.keySet())) {
        throw new IllegalArgumentException("Unknown domain tool argument");
      }
      String operation = requireString(arguments.get(OPERATION_FIELD), OPERATION_FIELD, id);
      MethodDescriptor tool = toolRegistry.findTool(name, operation);
      if (tool == null) {
        throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS,
            "Unknown operation " + operation + " for " + name);
      }
      Map<String, Object> operationParams = requireArguments(arguments.get(PARAMS_FIELD), id);
      Object result = dispatcher.dispatch(tool.name(), operationParams);
      if (dispatcher.isShuttingDown()) {
        closeSoon();
      }
      log.ok().status(200);
      return toolResult(Map.of(OPERATION_FIELD, operation, "result", result), false, statelessProtocol);
    } catch (Exception error) {
      log.error().status(200);
      return toolResult(errorPayload(error), true, statelessProtocol);
    }
  }

  private Map<String, Object> toolResult(Object result, boolean isError, boolean statelessProtocol) {
    Map<String, Object> content = new LinkedHashMap<>();
    content.put("type", "text");
    content.put("text", result instanceof String string ? string : JsonUtil.toJson(result));

    Map<String, Object> response = new LinkedHashMap<>();
    if (statelessProtocol) {
      response.put(RESULT_TYPE_FIELD, COMPLETE_RESULT);
    }
    response.put("content", List.of(content));
    response.put("structuredContent", structuredContent(result));
    response.put("isError", isError);
    return response;
  }

  private Object structuredContent(Object result) {
    if (result instanceof Map<?, ?>) {
      return result;
    }
    Map<String, Object> wrapper = new LinkedHashMap<>();
    wrapper.put("value", result);
    return wrapper;
  }

  static Map<String, Object> errorPayload(Exception exception) {
    return ApiFailures.normalize(exception).error().toMap();
  }

  private void closeSoon() {
    Thread shutdownThread =
        new Thread(
            () -> {
              try {
                Thread.sleep(100L);
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
              }
              close();
            },
            "ghidra-mcp-shutdown");
    shutdownThread.setDaemon(true);
    shutdownThread.start();
  }

  private static Map<String, Object> parseRequest(String body) {
    try {
      Object parsed = JsonUtil.parse(body);
      if (!(parsed instanceof Map<?, ?> map)) {
        throw new JsonRpcError(400, null, JSONRPC_INVALID_REQUEST, "Request must be a JSON object");
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> cast = (Map<String, Object>) map;
      return cast;
    } catch (JsonRpcError error) {
      throw error;
    } catch (IllegalArgumentException error) {
      throw new JsonRpcError(400, null, JSONRPC_PARSE_ERROR, "Invalid JSON request body", error);
    }
  }

  private static void validateJsonRpcEnvelope(Map<String, Object> request) {
    if (request.containsKey("id") && !isRequestId(request.get("id"))) {
      throw new JsonRpcError(400, null, JSONRPC_INVALID_REQUEST,
          "id must be a string or integer");
    }
    if (!JsonRpc.isVersion(request.get("jsonrpc"))) {
      throw new JsonRpcError(
          400, request.get("id"), JSONRPC_INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }
    if (!(request.get(METHOD_FIELD) instanceof String method) || method.isBlank()) {
      throw new JsonRpcError(
          400, request.get("id"), JSONRPC_INVALID_REQUEST, "method must be a non-empty string");
    }
  }

  private static boolean isRequestId(Object id) {
    return id instanceof String || (id instanceof Number number
        && Double.isFinite(number.doubleValue())
        && number.doubleValue() == Math.rint(number.doubleValue()));
  }

  private static boolean usesStatelessProtocol(
      HttpExchange exchange, Map<String, Object> request) {
    Map<String, Object> params = requireParamsMap(request.get(PARAMS_FIELD), request.get("id"));
    if (params.get("_meta") instanceof Map<?, ?> meta
        && (meta.containsKey("io.modelcontextprotocol/protocolVersion")
            || meta.containsKey("io.modelcontextprotocol/clientInfo")
            || meta.containsKey("io.modelcontextprotocol/clientCapabilities"))) {
      return true;
    }
    // Initialization negotiates its version in params before the HTTP headers control it.
    return !"initialize".equals(request.get(METHOD_FIELD))
        && (MCP_PROTOCOL_VERSION.equals(firstHeader(exchange, PROTOCOL_VERSION_HEADER))
            || "server/discover".equals(request.get(METHOD_FIELD)));
  }

  private static void validateInitializeProtocol(
      HttpExchange exchange, Map<String, Object> request) {
    String version = firstHeader(exchange, PROTOCOL_VERSION_HEADER);
    if (version == null
        || SUPPORTED_PROTOCOL_VERSIONS.contains(version)
        || INITIALIZE_PROTOCOL_VERSIONS.contains(version)) {
      return;
    }
    throw new JsonRpcError(400, request.get("id"), JSONRPC_INVALID_REQUEST,
        "Missing or unsupported MCP-Protocol-Version: " + version);
  }

  private static void validateMetadata(HttpExchange exchange, Map<String, Object> request) {
    Object id = request.get("id");
    Map<String, Object> params = requireParamsMap(request.get(PARAMS_FIELD), id);
    if (!(params.get("_meta") instanceof Map<?, ?> meta)
        || !(meta.get("io.modelcontextprotocol/protocolVersion") instanceof String)
        || !(meta.get("io.modelcontextprotocol/clientCapabilities") instanceof Map<?, ?>)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "Missing MCP request metadata");
    }
    if (meta.containsKey("io.modelcontextprotocol/clientInfo")) {
      validateImplementation(meta.get("io.modelcontextprotocol/clientInfo"), id);
    }
    Object version = meta.get("io.modelcontextprotocol/protocolVersion");
    if (!MCP_PROTOCOL_VERSION.equals(version)) {
      throw new JsonRpcError(400, id, UNSUPPORTED_PROTOCOL_VERSION,
          "UnsupportedProtocolVersionError", String.valueOf(version));
    }
    requireHeader(exchange, PROTOCOL_VERSION_HEADER, version.toString(), id);
    Object method = request.get(METHOD_FIELD);
    if (!(method instanceof String)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_REQUEST, "Missing method");
    }
    requireHeader(exchange, "Mcp-Method", method.toString(), id);
    if (TOOLS_CALL_METHOD.equals(method) || RESOURCES_READ_METHOD.equals(method)) {
      String key = TOOLS_CALL_METHOD.equals(method) ? NAME_FIELD : URI_FIELD;
      Object name = params.get(key);
      requireHeader(exchange, "Mcp-Name", name == null ? "" : name.toString(), id);
    }
  }

  private static void validateImplementation(Object value, Object id) {
    if (value == null) {
      return;
    }
    if (!(value instanceof Map<?, ?> info)
        || !(info.get(NAME_FIELD) instanceof String)
        || !(info.get("version") instanceof String)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS,
          "clientInfo must contain string name and version fields");
    }
  }

  private static void requireHeader(HttpExchange exchange, String header, String expected, Object id) {
    String actual = firstHeader(exchange, header);
    if (actual != null && actual.startsWith("=?base64?") && actual.endsWith("?=")) {
      try {
        actual = new String(java.util.Base64.getDecoder().decode(
            actual.substring(9, actual.length() - 2)), StandardCharsets.UTF_8);
      } catch (IllegalArgumentException invalid) {
        throw new JsonRpcError(400, id, HEADER_MISMATCH, "Invalid " + header + " encoding", invalid);
      }
    }
    if (!expected.equals(actual)) {
      throw new JsonRpcError(400, id, HEADER_MISMATCH, "HeaderMismatch: " + header);
    }
  }

  private static Map<String, Object> requireParamsMap(Object params, Object id) {
    if (params == null) {
      return Map.of();
    }
    if (params instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked")
      Map<String, Object> cast = (Map<String, Object>) map;
      return cast;
    }
    throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "params must be a JSON object");
  }

  private static Map<String, Object> requireArguments(Object arguments, Object id) {
    if (arguments == null) {
      return Map.of();
    }
    if (arguments instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked")
      Map<String, Object> cast = (Map<String, Object>) map;
      return cast;
    }
    throw new JsonRpcError(
        400, id, JSONRPC_INVALID_PARAMS, "tools/call arguments must be a JSON object");
  }

  private static String requireString(Object value, String field, Object id) {
    if (value instanceof String text && !text.isBlank()) {
      return text;
    }
    throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, field + " must be a non-empty string");
  }

  private boolean authorize(HttpExchange exchange) {
    String expectedToken = config.token();
    if (expectedToken == null) {
      return true;
    }
    return NetworkBinding.bearerTokenMatches(
        exchange.getRequestHeaders().getFirst("Authorization"), expectedToken);
  }

  private static boolean hasQueryToken(URI uri) {
    String query = uri.getQuery();
    if (query == null || query.isBlank()) return false;
    int parameterStart = 0;
    while (parameterStart <= query.length()) {
      int parameterEnd = query.indexOf('&', parameterStart);
      if (parameterEnd < 0) parameterEnd = query.length();
      int valueSeparator = query.indexOf('=', parameterStart);
      int nameEnd =
          valueSeparator >= parameterStart && valueSeparator < parameterEnd
              ? valueSeparator
              : parameterEnd;
      if (nameEnd - parameterStart == "token".length()
          && query.startsWith("token", parameterStart)) {
        return true;
      }
      if (parameterEnd == query.length()) return false;
      parameterStart = parameterEnd + 1;
    }
    return false;
  }

  private static void discardRequestLog(String ignored) {}

  private static String readBody(HttpExchange exchange) throws IOException {
    try (InputStream input = exchange.getRequestBody()) {
      return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static void writeJsonRpcError(
      HttpExchange exchange, int httpStatus, Object id, int code, String message)
      throws IOException {
    writeJson(exchange, httpStatus, mcpErrorResponse(exchange, id, code, message, null));
  }

  private static Map<String, Object> mcpErrorResponse(
      HttpExchange exchange, Object id, int code, String message, Map<String, Object> data) {
    Map<String, Object> response = data == null
        ? JsonRpc.errorResponse(id, code, message)
        : JsonRpc.errorResponse(id, code, message, data);
    if (!isRequestId(id)) {
      // The June error schema cannot express an unknown ID.
      // Follow the JSON-RPC null ID rule.
      if (JUNE_2025_PROTOCOL_VERSION.equals(firstHeader(exchange, PROTOCOL_VERSION_HEADER))) {
        response.put("id", null);
      } else {
        response.remove("id");
      }
    }
    return response;
  }

  private static Map<String, Object> success(Object id, Object result) {
    return JsonRpc.success(id, result);
  }

  private static void writeJson(HttpExchange exchange, int statusCode, Object payload)
      throws IOException {
    byte[] bytes = JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, "application/json; charset=utf-8");
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private static void writePlain(HttpExchange exchange, int statusCode, String payload)
      throws IOException {
    byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private static void sendNoBody(HttpExchange exchange, int statusCode) throws IOException {
    exchange.sendResponseHeaders(statusCode, -1);
  }

  private void addCommonHeaders(HttpExchange exchange) {
    String origin = firstHeader(exchange, "Origin");
    if (origin != null && !origin.isBlank()) {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
      exchange.getResponseHeaders().set("Vary", "Origin");
    } else {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
    }
    exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Accept");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Expose-Headers", PROTOCOL_VERSION_HEADER);
  }

  private boolean isAllowedOrigin(HttpExchange exchange) {
    String origin = firstHeader(exchange, "Origin");
    if (origin == null || origin.isBlank()) {
      return true;
    }
    try {
      URI uri = URI.create(origin);
      String host = uri.getHost();
      return host != null;
    } catch (IllegalArgumentException invalidOrigin) {
      return false;
    }
  }

  private static String firstHeader(HttpExchange exchange, String name) {
    List<String> values = exchange.getRequestHeaders().get(name);
    return values == null || values.isEmpty() ? null : values.get(0);
  }

  private static String serverVersion() {
    String version = McpHttpServer.class.getPackage().getImplementationVersion();
    return version == null || version.isBlank() ? "0.0.0-dev" : version;
  }

  private static String rootMessage(Throwable error) {
    Throwable current = error;
    while (current.getCause() != null) {
      current = current.getCause();
    }
    String message = current.getMessage();
    return message == null || message.isBlank() ? current.getClass().getName() : message;
  }

  private static final class JsonRpcError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int statusCode;
    private final transient Object requestId;
    private final int errorCode;
    private final String protocolVersion;

    JsonRpcError(int httpStatus, Object id, int code, String message) {
      this(httpStatus, id, code, message, (Throwable) null);
    }

    JsonRpcError(int httpStatus, Object id, int code, String message, Throwable cause) {
      super(message, cause);
      this.statusCode = httpStatus;
      this.requestId = id;
      this.errorCode = code;
      this.protocolVersion = null;
    }

    JsonRpcError(int httpStatus, Object id, int code, String message, String requestedVersion) {
      super(message);
      this.statusCode = httpStatus;
      this.requestId = id;
      this.errorCode = code;
      this.protocolVersion = requestedVersion;
    }

    int httpStatus() {
      return statusCode;
    }

    Object id() {
      return requestId;
    }

    int code() {
      return errorCode;
    }

    String requestedVersion() {
      return protocolVersion;
    }
  }

  private static String getQueryParameter(URI uri, String name) {
    String query = uri.getRawQuery();
    if (query == null || query.isBlank()) {
      return null;
    }
    for (String pair : query.split("&", -1)) {
      int eq = pair.indexOf('=');
      String key = eq >= 0 ? pair.substring(0, eq) : pair;
      if (key.equals(name)) {
        return eq >= 0
            ? java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8)
            : "";
      }
    }
    return null;
  }

  private static final class SseSession implements AutoCloseable {
    private final HttpExchange exchange;
    private final OutputStream output;
    private final AtomicBoolean active = new AtomicBoolean(true);

    SseSession(HttpExchange exchange) throws IOException {
      this.exchange = exchange;
      exchange.getResponseHeaders().set(CONTENT_TYPE_HEADER, "text/event-stream; charset=utf-8");
      exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-transform");
      exchange.getResponseHeaders().set("Connection", "keep-alive");
      exchange.getResponseHeaders().set("X-Accel-Buffering", "no");
      exchange.sendResponseHeaders(200, 0);
      this.output = exchange.getResponseBody();
    }

    synchronized void sendEvent(String event, String data) throws IOException {
      if (!active.get()) {
        return;
      }
      StringBuilder sb = new StringBuilder();
      if (event != null && !event.isBlank()) {
        sb.append("event: ").append(event).append("\n");
      }
      for (String line : data.split("\r?\n", -1)) {
        sb.append("data: ").append(line).append("\n");
      }
      sb.append("\n");
      output.write(sb.toString().getBytes(StandardCharsets.UTF_8));
      output.flush();
    }

    synchronized void sendComment(String comment) throws IOException {
      if (!active.get()) {
        return;
      }
      String payload = ": " + comment + "\n\n";
      output.write(payload.getBytes(StandardCharsets.UTF_8));
      output.flush();
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public void close() {
      if (active.compareAndSet(true, false)) {
        try {
          output.close();
        } catch (IOException ignored) {
          // Ignore close failure during session teardown.
        }
        try {
          exchange.close();
        } catch (RuntimeException ignored) {
          // Ignore close failure during session teardown.
        }
      }
    }

    boolean isActive() {
      return active.get();
    }
  }
}
