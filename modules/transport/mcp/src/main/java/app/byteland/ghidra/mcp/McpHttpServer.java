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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Streamable HTTP (POST-only) server that exposes the bridge API as grouped MCP tools and one
 * contract resource.
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
  private static final int HEADER_MISMATCH = -32020;
  private static final int UNSUPPORTED_PROTOCOL_VERSION = -32022;
  private static final String MCP_TOOLS_RESOURCE_URI = "ghidra-bridge://contracts/mcp-tools";
  private static final String HTTP_GET_METHOD = "GET";
  private static final String HTTP_OPTIONS_METHOD = "OPTIONS";
  private static final String HTTP_POST_METHOD = "POST";
  private static final String NAME_FIELD = "name";
  private static final String URI_FIELD = "uri";

  private final McpConfig config;
  private final AgentDispatcher dispatcher;
  private final Consumer<String> requestLogSink;
  private final McpToolRegistry toolRegistry;
  private final String toolContractJson;
  private final HttpServer server;
  private final ExecutorService executor;
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);
  private final AtomicBoolean closed = new AtomicBoolean(false);

  public McpHttpServer(McpConfig config, AgentDispatcher dispatcher) throws IOException {
    this(config, dispatcher, McpHttpServer::discardRequestLog);
  }

  public McpHttpServer(
      McpConfig config, AgentDispatcher dispatcher, Consumer<String> requestLogSink)
      throws IOException {
    this.config = Objects.requireNonNull(config, "config");
    this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    this.requestLogSink = Objects.requireNonNull(requestLogSink, "requestLogSink");
    this.toolRegistry = new McpToolRegistry(dispatcher.methodCatalog());
    Map<String, Object> toolContract = new LinkedHashMap<>();
    toolContract.put("protocol_version", MCP_PROTOCOL_VERSION);
    toolContract.put("tools", toolRegistry.listTools());
    this.toolContractJson = JsonUtil.toJson(toolContract);
    this.server = createServer(config);
    this.executor = Executors.newFixedThreadPool(4);
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

  public void start() {
    server.start();
  }

  public void awaitShutdown() throws InterruptedException {
    shutdownLatch.await();
  }

  public boolean awaitShutdown(BooleanSupplier cancelRequested) throws InterruptedException {
    return awaitShutdown(shutdownLatch, cancelRequested, this::close, 250L);
  }

  public String endpoint() {
    return config.endpoint();
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    server.stop(0);
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
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
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
          if (HTTP_GET_METHOD.equalsIgnoreCase(requestMethod)) {
            exchange.getResponseHeaders().set("Allow", "POST, OPTIONS");
            log.method(HTTP_GET_METHOD).error().status(405);
            writePlain(exchange, 405, "SSE streams are not implemented; use POST for JSON-RPC.");
            return;
          }

          if (!HTTP_POST_METHOD.equalsIgnoreCase(requestMethod)) {
            exchange.getResponseHeaders().set("Allow", "POST, OPTIONS");
            log.method(requestMethod).error().status(405);
            writeJsonRpcError(
                exchange,
                405,
                null,
                JSONRPC_INVALID_REQUEST,
                "Only POST is supported for this MCP endpoint");
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

          if (!String.valueOf(firstHeader(exchange, "Content-Type")).startsWith("application/json")) {
            throw new JsonRpcError(415, null, JSONRPC_INVALID_REQUEST, "Content-Type must be application/json");
          }
          Map<String, Object> request = parseRequest(readBody(exchange));
          validateMetadata(exchange, request);
          Object id = request.get("id");
          Object response = handleRequest(request, id, log);
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
          if (error.code() == UNSUPPORTED_PROTOCOL_VERSION) {
            writeJson(exchange, error.httpStatus(), JsonRpc.errorResponse(error.id(),
                error.code(), error.getMessage(), Map.of("requested", error.requestedVersion(),
                    "supported", List.of(MCP_PROTOCOL_VERSION))));
          } else {
            writeJsonRpcError(
                exchange, error.httpStatus(), error.id(), error.code(), error.getMessage());
          }
        } catch (IOException | RuntimeException error) {
          log.error().status(500).cause(rootMessage(error));
          writeJsonRpcError(exchange, 500, null, JSONRPC_INTERNAL_ERROR, "Internal error");
        } finally {
          log.finish();
        }
      }
    }
  }

  private Object handleRequest(Map<String, Object> request, Object id, RequestLog log) {
    validateJsonRpcEnvelope(request);
    String method = request.get("method").toString();
    log.method(method);
    if (!request.containsKey("id")) {
      return null;
    }
    Object params = request.get("params");
    log.id(id);

    return switch (method) {
      case "server/discover" -> {
        log.ok().status(200);
        yield success(id, discoveryResult());
      }
      case "ping" -> {
        log.ok().status(200);
        yield success(id, Map.of("resultType", "complete"));
      }
      case "tools/list" -> {
        log.ok().status(200);
        yield success(id, Map.of("resultType", "complete", "tools", toolRegistry.listTools()));
      }
      case "resources/list" -> {
        log.ok().status(200);
        yield success(id, Map.of("resultType", "complete", "resources", List.of(mcpToolsResource())));
      }
      case "resources/templates/list" -> {
        log.ok().status(200);
        yield success(id, Map.of("resultType", "complete", "resourceTemplates", List.of()));
      }
      case "resources/read" -> {
        log.ok().status(200);
        yield success(id, readResource(id, requireParamsMap(params, id)));
      }
      case "tools/call" -> {
        yield success(id, handleToolCall(id, requireParamsMap(params, id), log));
      }
      default ->
          throw new JsonRpcError(404, id, JSONRPC_METHOD_NOT_FOUND, "Method not found: " + method);
    };
  }

  private Map<String, Object> discoveryResult() {
    Map<String, Object> capabilities = new LinkedHashMap<>();
    capabilities.put("tools", Map.of("listChanged", false));
    capabilities.put("resources", Map.of("listChanged", false));

    Map<String, Object> serverInfo = new LinkedHashMap<>();
    serverInfo.put(NAME_FIELD, "ghidra-bridge");
    serverInfo.put("version", serverVersion());

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("resultType", "complete");
    result.put("supportedVersions", List.of(MCP_PROTOCOL_VERSION));
    result.put("capabilities", capabilities);
    result.put("_meta", Map.of("io.modelcontextprotocol/serverInfo", serverInfo));
    result.put(
        "instructions",
        "Use tools/list for the current callable contract, then tools/call to interact with the"
            + " active Ghidra program. The same tool contract is readable as an MCP resource.");
    return result;
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

  private Map<String, Object> readResource(Object id, Map<String, Object> params) {
    String uri = requireString(params.get(URI_FIELD), URI_FIELD, id);
    if (!MCP_TOOLS_RESOURCE_URI.equals(uri)) {
      throw new JsonRpcError(404, id, JSONRPC_RESOURCE_NOT_FOUND, "Resource not found: " + uri);
    }
    Map<String, Object> content = new LinkedHashMap<>();
    content.put(URI_FIELD, MCP_TOOLS_RESOURCE_URI);
    content.put("mimeType", "application/json");
    content.put("text", toolContractJson);
    return Map.of("resultType", "complete", "contents", List.of(content));
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private Map<String, Object> handleToolCall(
      Object id, Map<String, Object> params, RequestLog log) {
    String name = requireString(params.get(NAME_FIELD), NAME_FIELD, id);
    log.tool(name);
    if (!toolRegistry.hasTool(name)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + name);
    }
    Map<String, Object> arguments = requireArguments(params.get("arguments"), id);
    try {
      if (name.equals("ghidra.help")) {
        log.ok().status(200);
        return toolResult(toolRegistry.help(arguments), false);
      }
      if (!List.of("operation", "params").containsAll(arguments.keySet())) {
        throw new IllegalArgumentException("Unknown domain tool argument");
      }
      String operation = requireString(arguments.get("operation"), "operation", id);
      MethodDescriptor tool = toolRegistry.findTool(name, operation);
      if (tool == null) {
        throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS,
            "Unknown operation " + operation + " for " + name);
      }
      Map<String, Object> operationParams = requireArguments(arguments.get("params"), id);
      Object result = dispatcher.dispatch(tool.name(), operationParams);
      if (dispatcher.isShuttingDown()) {
        closeSoon();
      }
      log.ok().status(200);
      return toolResult(Map.of("operation", operation, "result", result), false);
    } catch (Exception error) {
      log.error().status(200);
      return toolResult(errorPayload(error), true);
    }
  }

  private Map<String, Object> toolResult(Object result, boolean isError) {
    Map<String, Object> content = new LinkedHashMap<>();
    content.put("type", "text");
    content.put("text", result instanceof String string ? string : JsonUtil.toJson(result));

    Map<String, Object> response = new LinkedHashMap<>();
    response.put("resultType", "complete");
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
    if (!JsonRpc.isVersion(request.get("jsonrpc"))) {
      throw new JsonRpcError(
          400, request.get("id"), JSONRPC_INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }
    if (!(request.get("method") instanceof String method) || method.isBlank()) {
      throw new JsonRpcError(
          400, request.get("id"), JSONRPC_INVALID_REQUEST, "method must be a non-empty string");
    }
  }

  private static void validateMetadata(HttpExchange exchange, Map<String, Object> request) {
    Object id = request.get("id");
    Map<String, Object> params = requireParamsMap(request.get("params"), id);
    if (!(params.get("_meta") instanceof Map<?, ?> meta)
        || !(meta.get("io.modelcontextprotocol/clientInfo") instanceof Map<?, ?>)
        || !(meta.get("io.modelcontextprotocol/clientCapabilities") instanceof Map<?, ?>)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "Missing MCP request metadata");
    }
    Object version = meta.get("io.modelcontextprotocol/protocolVersion");
    if (!MCP_PROTOCOL_VERSION.equals(version)) {
      throw new JsonRpcError(400, id, UNSUPPORTED_PROTOCOL_VERSION,
          "UnsupportedProtocolVersionError", String.valueOf(version));
    }
    requireHeader(exchange, "MCP-Protocol-Version", version.toString(), id);
    Object method = request.get("method");
    if (!(method instanceof String)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_REQUEST, "Missing method");
    }
    requireHeader(exchange, "Mcp-Method", method.toString(), id);
    if (method.equals("tools/call") || method.equals("resources/read")) {
      String key = method.equals("tools/call") ? "name" : "uri";
      Object name = params.get(key);
      requireHeader(exchange, "Mcp-Name", name == null ? "" : name.toString(), id);
    }
  }

  private static void requireHeader(HttpExchange exchange, String header, String expected, Object id) {
    String actual = firstHeader(exchange, header);
    if (actual != null && actual.startsWith("=?base64?") && actual.endsWith("?=")) {
      try {
        actual = new String(java.util.Base64.getDecoder().decode(
            actual.substring(9, actual.length() - 2)), StandardCharsets.UTF_8);
      } catch (IllegalArgumentException invalid) {
        throw new JsonRpcError(400, id, HEADER_MISMATCH, "Invalid " + header + " encoding");
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
    writeJson(exchange, httpStatus, JsonRpc.errorResponse(id, code, message));
  }

  private static Map<String, Object> success(Object id, Object result) {
    return JsonRpc.success(id, result);
  }

  private static void writeJson(HttpExchange exchange, int statusCode, Object payload)
      throws IOException {
    byte[] bytes = JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private static void writePlain(HttpExchange exchange, int statusCode, String payload)
      throws IOException {
    byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
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
    }
    exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version");
  }

  private boolean isAllowedOrigin(HttpExchange exchange) {
    String origin = firstHeader(exchange, "Origin");
    if (origin == null || origin.isBlank()) {
      return true;
    }
    try {
      URI uri = URI.create(origin);
      String host = uri.getHost();
      return host != null && (config.host().equalsIgnoreCase(host) || isLoopbackOriginHost(host));
    } catch (IllegalArgumentException invalidOrigin) {
      return false;
    }
  }

  private static boolean isLoopbackOriginHost(String host) {
    try {
      return NetworkBinding.isLoopback(host);
    } catch (IllegalArgumentException unresolvedHost) {
      return false;
    }
  }

  private static String firstHeader(HttpExchange exchange, String name) {
    List<String> values = exchange.getRequestHeaders().get(name);
    return values == null || values.isEmpty() ? null : values.get(0);
  }

  private static String serverVersion() {
    String version = McpHttpServer.class.getPackage().getImplementationVersion();
    return version == null || version.isBlank() ? "0.2.0" : version;
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
    private final String requestedVersion;

    JsonRpcError(int httpStatus, Object id, int code, String message) {
      this(httpStatus, id, code, message, (Throwable) null);
    }

    JsonRpcError(int httpStatus, Object id, int code, String message, Throwable cause) {
      super(message, cause);
      this.statusCode = httpStatus;
      this.requestId = id;
      this.errorCode = code;
      this.requestedVersion = null;
    }

    JsonRpcError(int httpStatus, Object id, int code, String message, String requestedVersion) {
      super(message);
      this.statusCode = httpStatus;
      this.requestId = id;
      this.errorCode = code;
      this.requestedVersion = requestedVersion;
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
      return requestedVersion;
    }
  }
}
