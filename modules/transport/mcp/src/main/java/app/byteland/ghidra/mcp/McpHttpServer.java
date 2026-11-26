package app.byteland.ghidra.mcp;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.api.BridgeError;
import app.byteland.ghidra.network.NetworkBinding;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * HTTP server that exposes the bridge API as grouped MCP tools through Streamable HTTP and SSE.
 */
public final class McpHttpServer implements AutoCloseable {
  static final int MAX_CONCURRENT_REQUESTS = 32;
  static final int MAX_SSE_SESSIONS = 16;
  static final int MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024;
  static final int MAX_TOOL_RESULT_BYTES = 8 * 1024 * 1024 + 65_536;
  static final int MAX_HTTP_RESPONSE_BYTES = 3 * MAX_TOOL_RESULT_BYTES + 4096;
  static final Duration DEFAULT_BODY_READ_TIMEOUT = Duration.ofSeconds(10);
  static final Duration DEFAULT_SSE_KEEPALIVE_INTERVAL = Duration.ofSeconds(15);
  private static final int LISTEN_BACKLOG = 256;
  private static final int HTTP_PAYLOAD_TOO_LARGE = 413;
  private static final int JSONRPC_PARSE_ERROR = -32700;
  private static final int JSONRPC_INVALID_REQUEST = -32600;
  private static final int JSONRPC_METHOD_NOT_FOUND = -32601;
  private static final int JSONRPC_INVALID_PARAMS = -32602;
  private static final int JSONRPC_INTERNAL_ERROR = -32603;
  private static final int JSONRPC_SERVER_BUSY = -32000;
  private static final int JSONRPC_UNAUTHORIZED = -32001;
  private static final int JSONRPC_RESOURCE_NOT_FOUND = -32002;
  private static final String MCP_PROTOCOL_VERSION = "2026-07-28";
  private static final String INITIALIZE_PROTOCOL_VERSION = "2025-11-25";
  private static final List<String> INITIALIZE_PROTOCOL_VERSIONS =
      List.of("2024-11-05", "2025-03-26", "2025-06-18", INITIALIZE_PROTOCOL_VERSION);
  private static final List<String> SUPPORTED_PROTOCOL_VERSIONS =
      List.of(MCP_PROTOCOL_VERSION, INITIALIZE_PROTOCOL_VERSION, "2025-06-18", "2025-03-26", "2024-11-05");
  private static final int HEADER_MISMATCH = -32020;
  private static final int UNSUPPORTED_PROTOCOL_VERSION = -32022;
  private static final String LEGACY_MCP_TOOLS_RESOURCE_URI =
      "ghidra-bridge://contracts/mcp-tools";
  private static final String SCOPED_RESOURCE_URI_PREFIX = "ghidra-bridge://";
  private static final String SCOPED_RESOURCE_URI_SUFFIX = "/contracts/mcp-tools";
  private static final String HTTP_GET_METHOD = "GET";
  private static final String HTTP_OPTIONS_METHOD = "OPTIONS";
  private static final String HTTP_POST_METHOD = "POST";
  private static final String NAME_FIELD = "name";
  private static final String URI_FIELD = "uri";
  private static final String SESSION_ID_PARAM = "sessionId";

  private final McpConfig config;
  private final boolean loopbackListener;
  private final String normalizedConfiguredHost;
  private final InetAddress configuredHostLiteral;
  private final AgentDispatcher dispatcher;
  private final Consumer<String> requestLogSink;
  private final McpToolRegistry toolRegistry;
  private final String mcpToolsResourceUri;
  private final String toolContractJson;
  private final HttpServer server;
  private final ExecutorService executor;
  private final ExecutorService bodyReaderExecutor;
  private final ScheduledExecutorService readTimeoutScheduler;
  private final long bodyReadTimeoutMillis;
  private final long sseKeepaliveMillis;
  private final Semaphore requestPermits = new Semaphore(MAX_CONCURRENT_REQUESTS);
  private final Semaphore sseSessionPermits = new Semaphore(MAX_SSE_SESSIONS);
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final ConcurrentHashMap<String, SseSession> sseSessions = new ConcurrentHashMap<>();

  public McpHttpServer(McpConfig config, AgentDispatcher dispatcher) throws IOException {
    this(config, dispatcher, McpHttpServer::discardRequestLog);
  }

  public McpHttpServer(
      McpConfig config, AgentDispatcher dispatcher, Consumer<String> requestLogSink)
      throws IOException {
    this(
        config,
        dispatcher,
        requestLogSink,
        DEFAULT_BODY_READ_TIMEOUT,
        DEFAULT_SSE_KEEPALIVE_INTERVAL);
  }

  McpHttpServer(
      McpConfig config,
      AgentDispatcher dispatcher,
      Consumer<String> requestLogSink,
      long sseKeepaliveMillis)
      throws IOException {
    this(
        config,
        dispatcher,
        requestLogSink,
        DEFAULT_BODY_READ_TIMEOUT.toMillis(),
        sseKeepaliveMillis);
  }

  McpHttpServer(
      McpConfig config,
      AgentDispatcher dispatcher,
      Consumer<String> requestLogSink,
      Duration bodyReadTimeout,
      Duration sseKeepaliveInterval)
      throws IOException {
    this(
        config,
        dispatcher,
        requestLogSink,
        positiveDurationMillis(bodyReadTimeout, "bodyReadTimeout"),
        positiveDurationMillis(sseKeepaliveInterval, "sseKeepaliveInterval"));
  }

  private McpHttpServer(
      McpConfig config,
      AgentDispatcher dispatcher,
      Consumer<String> requestLogSink,
      long bodyReadTimeoutMillis,
      long sseKeepaliveMillis)
      throws IOException {
    if (bodyReadTimeoutMillis <= 0L) {
      throw new IllegalArgumentException("bodyReadTimeoutMillis must be positive");
    }
    if (sseKeepaliveMillis <= 0L) {
      throw new IllegalArgumentException("sseKeepaliveMillis must be positive");
    }
    this.config = Objects.requireNonNull(config, "config");
    this.loopbackListener = NetworkBinding.isLoopback(config.host());
    this.normalizedConfiguredHost = normalizeHost(config.host());
    this.configuredHostLiteral = NetworkBinding.parseIpLiteral(this.normalizedConfiguredHost);
    this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    this.requestLogSink = Objects.requireNonNull(requestLogSink, "requestLogSink");
    this.bodyReadTimeoutMillis = bodyReadTimeoutMillis;
    this.sseKeepaliveMillis = sseKeepaliveMillis;
    this.toolRegistry = new McpToolRegistry(dispatcher.methodCatalog(), config.toolPrefix());
    this.mcpToolsResourceUri =
        SCOPED_RESOURCE_URI_PREFIX + config.toolPrefix() + SCOPED_RESOURCE_URI_SUFFIX;
    Map<String, Object> toolContract = new LinkedHashMap<>();
    toolContract.put("protocol_version", MCP_PROTOCOL_VERSION);
    toolContract.put("tools", toolRegistry.listTools());
    this.toolContractJson = JsonUtil.toJson(toolContract);
    this.server = createServer(config);
    this.executor = Executors.newVirtualThreadPerTaskExecutor();
    this.bodyReaderExecutor = createBodyReaderExecutor();
    this.readTimeoutScheduler = createReadTimeoutScheduler();
    this.server.setExecutor(executor);
    this.server.createContext(config.path(), new JsonRpcHandler());
  }

  private static long positiveDurationMillis(Duration duration, String name) {
    Objects.requireNonNull(duration, name);
    if (duration.isZero() || duration.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
    return Math.max(1L, duration.toMillis());
  }

  private static ExecutorService createBodyReaderExecutor() {
    // `jdk.httpserver` synchronizes `LeftOverInputStream.read` and `Request$ReadStream.read`.
    // On Java 21, an unbuffered body read on a virtual thread pins its carrier without
    // `ForkJoinPool` compensation. Run unbuffered reads on a daemon pool of size
    // `MAX_CONCURRENT_REQUESTS` so stalled `POST` bodies do not block carriers or later reads.
    AtomicInteger threadNumber = new AtomicInteger(1);
    ThreadPoolExecutor pool =
        new ThreadPoolExecutor(
            MAX_CONCURRENT_REQUESTS,
            MAX_CONCURRENT_REQUESTS,
            5L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(MAX_CONCURRENT_REQUESTS),
            runnable -> {
              Thread thread =
                  new Thread(runnable, "ghidra-mcp-body-reader-" + threadNumber.getAndIncrement());
              thread.setDaemon(true);
              return thread;
            });
    pool.allowCoreThreadTimeOut(true);
    return pool;
  }

  private static ScheduledExecutorService createReadTimeoutScheduler() {
    ScheduledThreadPoolExecutor scheduler =
        new ScheduledThreadPoolExecutor(
            1,
            runnable -> {
              Thread thread = new Thread(runnable, "ghidra-mcp-read-timeout");
              thread.setDaemon(true);
              return thread;
            });
    scheduler.setRemoveOnCancelPolicy(true);
    scheduler.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
    return scheduler;
  }

  private static HttpServer createServer(McpConfig config) throws IOException {
    try {
      return HttpServer.create(
          new InetSocketAddress(config.host(), config.port()), LISTEN_BACKLOG);
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

  public boolean awaitShutdown(BooleanSupplier cancelRequested) throws InterruptedException {
    return awaitShutdown(shutdownLatch, cancelRequested, this::close, 250L);
  }

  public String endpoint() {
    return config.endpoint();
  }

  int availableRequestPermits() {
    return requestPermits.availablePermits();
  }

  int activeSseSessionCount() {
    return sseSessions.size();
  }

  @Override
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
    ExecutorShutdown.shutdownAndAwait(bodyReaderExecutor);
    ExecutorShutdown.shutdownAndAwait(readTimeoutScheduler);
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
    public void handle(HttpExchange exchange) throws IOException {
      RequestLog log = new RequestLog(requestLogSink);
      Object requestId = null;
      boolean requestPermitAcquired = false;
      boolean bodyRead = false;
      boolean closeExchange = true;
      try {
        NetworkBinding.HostValidationResult hostValidation = validateHost(exchange);
        if (!hostValidation.isValid()) {
          int status = hostValidation.httpStatus();
          log.method(exchange.getRequestMethod()).error().status(status);
          writePlainResponse(exchange, status, hostValidation.message(), false);
          return;
        }
        OriginValidation originValidation = validateOrigin(exchange);
        if (!originValidation.allowed()) {
          log.method(exchange.getRequestMethod()).error().status(403);
          writePlainResponse(exchange, 403, "Forbidden origin", false);
          return;
        }
        addCommonHeaders(exchange, originValidation.origin());

        String requestMethod = exchange.getRequestMethod();
        if (HTTP_OPTIONS_METHOD.equalsIgnoreCase(requestMethod)) {
          log.method(HTTP_OPTIONS_METHOD).ok().status(204);
          sendNoBody(exchange, 204);
          return;
        }
        if ("HEAD".equalsIgnoreCase(requestMethod)) {
          log.method("HEAD").ok().status(200);
          sendNoBody(exchange, 200);
          return;
        }

        if (hasQueryToken(exchange.getRequestURI())) {
          log.error().status(400);
          writeJsonRpcErrorResponse(
              exchange,
              400,
              null,
              JSONRPC_INVALID_REQUEST,
              "Query-string tokens are not supported",
              false);
          return;
        }

        if (!authorize(exchange)) {
          exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
          log.error().status(401);
          writeJsonRpcErrorResponse(
              exchange, 401, null, JSONRPC_UNAUTHORIZED, "Unauthorized", false);
          return;
        }

        if (HTTP_GET_METHOD.equalsIgnoreCase(requestMethod)) {
          handleSseGet(exchange, log);
          return;
        }

        if (!HTTP_POST_METHOD.equalsIgnoreCase(requestMethod)) {
          exchange.getResponseHeaders().set("Allow", "POST, GET, OPTIONS");
          log.method(requestMethod).error().status(405);
          writeJsonRpcErrorResponse(
              exchange,
              405,
              null,
              JSONRPC_INVALID_REQUEST,
              "Only POST and GET (SSE) are supported for this MCP endpoint",
              false);
          return;
        }

        if (!requestPermits.tryAcquire()) {
          exchange.getResponseHeaders().set("Connection", "close");
          log.method(HTTP_POST_METHOD).error().status(503);
          writeJsonRpcErrorResponse(
              exchange, 503, null, JSONRPC_SERVER_BUSY, "Too many concurrent requests", false);
          return;
        }
        requestPermitAcquired = true;

        String sessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
        SseSession sseSession = null;
        if (sessionId != null) {
          sseSession = sseSessions.get(sessionId);
          if (sseSession == null || !sseSession.isActive()) {
            log.error().status(404);
            writeJsonRpcErrorResponse(
                exchange,
                404,
                null,
                JSONRPC_INVALID_REQUEST,
                "SSE session not found or expired",
                false);
            return;
          }
        }

        validateContentLength(exchange.getRequestHeaders());
        if (!String.valueOf(firstHeader(exchange, "Content-Type")).startsWith("application/json")) {
          throw new JsonRpcError(
              415, null, JSONRPC_INVALID_REQUEST, "Content-Type must be application/json");
        }
        String rawBody = readRequestBody(exchange);
        bodyRead = true;
        Map<String, Object> request = parseRequest(rawBody);
        validateJsonRpcEnvelope(request);
        boolean statelessProtocol = usesStatelessProtocol(exchange, request);
        if (statelessProtocol) {
          validateMetadata(exchange, request);
        } else {
          validateInitializeProtocol(exchange, request);
        }
        Object id = request.get("id");
        requestId = id;
        Object response = handleRequest(request, id, log, statelessProtocol);
        if (sseSession != null) {
          if (response != null) {
            sseSession.sendEvent("message", JsonUtil.toJson(response, MAX_HTTP_RESPONSE_BYTES));
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
      } catch (UnreadRequestAbortedException abortedUnread) {
        closeExchange = false;
        throw abortedUnread;
      } catch (ApiException error) {
        log.error()
            .status(error.status())
            .id(requestId)
            .cause(error.status() >= 500 ? rootMessage(error) : null);
        if (error.status() == HTTP_PAYLOAD_TOO_LARGE) {
          exchange.getResponseHeaders().set("Connection", "close");
        }
        Map<String, Object> errResponse =
            mcpErrorResponse(
                exchange,
                requestId,
                JSONRPC_INTERNAL_ERROR,
                error.getMessage(),
                error.error().toMap());
        String querySessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
        SseSession activeSse = querySessionId == null ? null : sseSessions.get(querySessionId);
        if (activeSse != null && activeSse.isActive()) {
          try {
            activeSse.sendEvent(
                "message", JsonUtil.toJson(errResponse, MAX_HTTP_RESPONSE_BYTES));
          } catch (IOException ignored) {
          }
          exchange.sendResponseHeaders(202, -1);
        } else {
          try {
            writeJsonResponse(exchange, error.status(), errResponse, bodyRead);
          } catch (UnreadRequestAbortedException abortedUnread) {
            closeExchange = false;
            throw abortedUnread;
          }
        }
      } catch (JsonRpcError error) {
        log.error()
            .status(error.httpStatus())
            .id(error.id())
            .cause(error.httpStatus() >= 500 ? rootMessage(error) : null);
        if (error.httpStatus() == HTTP_PAYLOAD_TOO_LARGE) {
          exchange.getResponseHeaders().set("Connection", "close");
        }
        Map<String, Object> errResponse =
            error.code() == UNSUPPORTED_PROTOCOL_VERSION
                ? mcpErrorResponse(
                    exchange,
                    error.id(),
                    error.code(),
                    error.getMessage(),
                    Map.of(
                        "requested",
                        error.requestedVersion(),
                        "supported",
                        SUPPORTED_PROTOCOL_VERSIONS))
                : mcpErrorResponse(exchange, error.id(), error.code(), error.getMessage(), null);
        String querySessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
        SseSession activeSse = querySessionId == null ? null : sseSessions.get(querySessionId);
        if (activeSse != null && activeSse.isActive()) {
          try {
            activeSse.sendEvent(
                "message", JsonUtil.toJson(errResponse, MAX_HTTP_RESPONSE_BYTES));
          } catch (IOException ignored) {
          }
          if (error.httpStatus() == HTTP_PAYLOAD_TOO_LARGE) {
            closeExchange = false;
            writePayloadTooLargeResponse(exchange, errResponse);
          } else if (bodyRead || !hasRequestBody(exchange) || isCompleteBodyBuffered(exchange)) {
            exchange.sendResponseHeaders(202, -1);
          } else {
            exchange.getResponseHeaders().set("Connection", "close");
            exchange.sendResponseHeaders(202, -1);
            pauseBeforeUnreadClose();
            closeExchange = false;
            throw new UnreadRequestAbortedException();
          }
        } else if (error.httpStatus() == HTTP_PAYLOAD_TOO_LARGE) {
          closeExchange = false;
          writePayloadTooLargeResponse(exchange, errResponse);
        } else {
          try {
            writeJsonResponse(exchange, error.httpStatus(), errResponse, bodyRead);
          } catch (UnreadRequestAbortedException abortedUnread) {
            closeExchange = false;
            throw abortedUnread;
          }
        }
      } catch (BodyReadTimeoutException timeout) {
        log.method(HTTP_POST_METHOD).error().status(408).cause("Request body read timed out");
      } catch (IOException | RuntimeException error) {
        log.error().status(500).cause(rootMessage(error));
        try {
          writeJsonRpcErrorResponse(
              exchange, 500, null, JSONRPC_INTERNAL_ERROR, "Internal error", bodyRead);
        } catch (UnreadRequestAbortedException abortedUnread) {
          closeExchange = false;
          throw abortedUnread;
        } catch (IOException ignored) {
          // The connection closed before the server could send the error response.
        }
      } finally {
        if (requestPermitAcquired) {
          requestPermits.release();
        }
        log.finish();
        if (closeExchange) {
          exchange.close();
        }
      }
    }

    private void handleSseGet(HttpExchange exchange, RequestLog log) throws IOException {
      if (!sseSessionPermits.tryAcquire()) {
        exchange.getResponseHeaders().set("Connection", "close");
        log.method(HTTP_GET_METHOD).error().status(503);
        writeJsonRpcError(
            exchange, 503, null, JSONRPC_SERVER_BUSY, "Too many active SSE sessions");
        return;
      }
      try {
        String sessionId = UUID.randomUUID().toString();
        SseSession session;
        try {
          session = new SseSession(exchange);
        } catch (IOException error) {
          log.method(HTTP_GET_METHOD).error().status(500);
          return;
        }
        sseSessions.put(sessionId, session);
        log.method(HTTP_GET_METHOD).ok().status(200);

        try {
          String endpointUri = config.path() + "?" + SESSION_ID_PARAM + "=" + sessionId;
          session.sendEvent("endpoint", endpointUri);

          while (session.isActive() && !closed.get()) {
            try {
              if (session.awaitClose(sseKeepaliveMillis, TimeUnit.MILLISECONDS)) {
                break;
              }
              if (closed.get()) {
                break;
              }
              session.sendComment("keepalive");
            } catch (InterruptedException interrupted) {
              Thread.currentThread().interrupt();
              break;
            }
          }
        } catch (IOException clientDisconnected) {
          // The SSE client disconnected.
        } finally {
          sseSessions.remove(sessionId);
          session.closeAndAwaitStream();
        }
      } finally {
        sseSessionPermits.release();
      }
    }
  }

  private Object handleRequest(
      Map<String, Object> request, Object id, RequestLog log, boolean statelessProtocol) {
    String method = request.get("method").toString();
    log.method(method);
    if (!request.containsKey("id")) {
      return null;
    }
    Object params = request.get("params");
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
        yield success(id, statelessProtocol ? Map.of("resultType", "complete") : Map.of());
      }
      case "tools/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of("resultType", "complete", "tools", toolRegistry.listTools()), true)
            : Map.of("tools", toolRegistry.listTools()));
      }
      case "resources/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of("resultType", "complete", "resources", List.of(mcpToolsResource())), true)
            : Map.of("resources", List.of(mcpToolsResource())));
      }
      case "resources/templates/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of("resultType", "complete", "resourceTemplates", List.of()), true)
            : Map.of("resourceTemplates", List.of()));
      }
      case "resources/read" -> {
        log.ok().status(200);
        yield success(id, cacheableResult(
            readResource(id, requireParamsMap(params, id), statelessProtocol), statelessProtocol));
      }
      case "tools/call" -> {
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
    if (!(params.get("capabilities") instanceof Map<?, ?>)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "capabilities must be a JSON object");
    }
    validateImplementation(params.get("clientInfo"), id);
    Map<String, Object> discovery = discoveryResult();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("protocolVersion", INITIALIZE_PROTOCOL_VERSIONS.contains(requestedVersion)
        ? requestedVersion : INITIALIZE_PROTOCOL_VERSION);
    result.put("capabilities", discovery.get("capabilities"));
    result.put("serverInfo", Map.of(NAME_FIELD, "ghidra-bridge", "version", serverVersion()));
    result.put("instructions", discovery.get("instructions"));
    return result;
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
    result.put("supportedVersions", SUPPORTED_PROTOCOL_VERSIONS);
    result.put("capabilities", capabilities);
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
    resource.put(URI_FIELD, mcpToolsResourceUri);
    resource.put(NAME_FIELD, "mcp-tools");
    resource.put("title", "Ghidra Bridge MCP tool contract");
    resource.put("description", "The current callable Ghidra Bridge tool catalog and schemas.");
    resource.put("mimeType", "application/json");
    return resource;
  }

  private Map<String, Object> readResource(
      Object id, Map<String, Object> params, boolean statelessProtocol) {
    String uri = requireString(params.get(URI_FIELD), URI_FIELD, id);
    boolean matchesScoped = mcpToolsResourceUri.equals(uri);
    boolean matchesLegacyDefault =
        McpConfig.DEFAULT_TOOL_PREFIX.equals(config.toolPrefix())
            && LEGACY_MCP_TOOLS_RESOURCE_URI.equals(uri);
    if (!matchesScoped && !matchesLegacyDefault) {
      throw new JsonRpcError(statelessProtocol ? 400 : 404, id,
          statelessProtocol ? JSONRPC_INVALID_PARAMS : JSONRPC_RESOURCE_NOT_FOUND,
          "Resource not found: " + uri);
    }
    Map<String, Object> content = new LinkedHashMap<>();
    content.put(URI_FIELD, uri);
    content.put("mimeType", "application/json");
    content.put("text", toolContractJson);
    return statelessProtocol
        ? Map.of("resultType", "complete", "contents", List.of(content))
        : Map.of("contents", List.of(content));
  }

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
        Map<String, Object> response =
            toolResult(toolRegistry.help(arguments), false, statelessProtocol);
        log.ok().status(200);
        return response;
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
      Map<String, Object> response =
          toolResult(Map.of("operation", operation, "result", result), false, statelessProtocol);
      log.ok().status(200);
      return response;
    } catch (Exception error) {
      log.error().status(200);
      try {
        return toolResult(errorPayload(error), true, statelessProtocol);
      } catch (ApiException oversizedError) {
        return toolResult(
            new BridgeError(
                    413,
                    "response_too_large",
                    "Tool error response exceeds maximum size",
                    null,
                    Map.of())
                .toMap(),
            true,
            statelessProtocol);
      }
    }
  }

  static Map<String, Object> toolResult(
      Object result, boolean isError, boolean statelessProtocol) {
    Map<String, Object> content = new LinkedHashMap<>();
    content.put("type", "text");
    Object structured;
    if (result instanceof String string) {
      JsonUtil.utf8ByteLength(string, MAX_TOOL_RESULT_BYTES);
      content.put("text", string);
      structured = structuredContent(result, string);
    } else {
      String json = JsonUtil.toJson(result, MAX_TOOL_RESULT_BYTES);
      content.put("text", json);
      structured = structuredContent(result, JsonUtil.rawJson(json));
    }

    Map<String, Object> response = new LinkedHashMap<>();
    if (statelessProtocol) {
      response.put("resultType", "complete");
    }
    response.put("content", List.of(content));
    response.put("structuredContent", structured);
    response.put("isError", isError);
    return response;
  }

  private static Object structuredContent(Object original, Object encoded) {
    if (original instanceof Map<?, ?>) {
      return encoded;
    }
    Map<String, Object> wrapper = new LinkedHashMap<>();
    wrapper.put("value", encoded);
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
    if (!(request.get("method") instanceof String method) || method.isBlank()) {
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
    Map<String, Object> params = requireParamsMap(request.get("params"), request.get("id"));
    if (params.get("_meta") instanceof Map<?, ?> meta
        && (meta.containsKey("io.modelcontextprotocol/protocolVersion")
            || meta.containsKey("io.modelcontextprotocol/clientInfo")
            || meta.containsKey("io.modelcontextprotocol/clientCapabilities"))) {
      return true;
    }
    // Initialization negotiates its version in params before the HTTP headers control it.
    return !"initialize".equals(request.get("method"))
        && (MCP_PROTOCOL_VERSION.equals(firstHeader(exchange, "MCP-Protocol-Version"))
            || "server/discover".equals(request.get("method")));
  }

  private static void validateInitializeProtocol(
      HttpExchange exchange, Map<String, Object> request) {
    String version = firstHeader(exchange, "MCP-Protocol-Version");
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
    Map<String, Object> params = requireParamsMap(request.get("params"), id);
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

  private String readRequestBody(HttpExchange exchange) throws IOException {
    if (closed.get()) {
      exchange.close();
      throw new IOException("MCP server is closed");
    }
    if (isCompleteBodyBuffered(exchange)) {
      return readBody(exchange);
    }
    AtomicBoolean finished = new AtomicBoolean(false);
    AtomicBoolean timedOut = new AtomicBoolean(false);
    ScheduledFuture<?> timeoutTask;
    try {
      timeoutTask =
          readTimeoutScheduler.schedule(
              () -> {
                if (finished.compareAndSet(false, true)) {
                  timedOut.set(true);
                  exchange.close();
                }
              },
              bodyReadTimeoutMillis,
              TimeUnit.MILLISECONDS);
    } catch (RejectedExecutionException rejected) {
      exchange.close();
      throw new IOException("MCP server is shutting down", rejected);
    }
    Future<String> readFuture = null;
    try {
      readFuture = bodyReaderExecutor.submit(() -> readBody(exchange));
      String body = readFuture.get();
      if (!finished.compareAndSet(false, true)) {
        throw new BodyReadTimeoutException(null);
      }
      return body;
    } catch (RejectedExecutionException rejected) {
      exchange.close();
      throw new IOException("MCP server is shutting down", rejected);
    } catch (InterruptedException interrupted) {
      if (readFuture != null) {
        readFuture.cancel(true);
      }
      exchange.close();
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while reading request body", interrupted);
    } catch (ExecutionException failed) {
      Throwable cause = failed.getCause();
      if (timedOut.get()) {
        throw new BodyReadTimeoutException(cause);
      }
      if (cause instanceof IOException ioError) {
        throw ioError;
      }
      if (cause instanceof RuntimeException runtimeError) {
        throw runtimeError;
      }
      throw new IOException("Failed to read request body", cause);
    } finally {
      finished.set(true);
      timeoutTask.cancel(false);
    }
  }

  private static boolean isCompleteBodyBuffered(HttpExchange exchange) throws IOException {
    if (firstHeader(exchange, "Transfer-Encoding") != null) {
      return false;
    }
    String rawContentLength = firstHeader(exchange, "Content-Length");
    if (rawContentLength == null) {
      return false;
    }
    long contentLength;
    try {
      contentLength = Long.parseLong(rawContentLength.trim());
    } catch (NumberFormatException invalid) {
      return false;
    }
    if (contentLength < 0L || contentLength > MAX_REQUEST_BODY_BYTES) {
      return false;
    }
    return contentLength == 0L || exchange.getRequestBody().available() >= contentLength;
  }

  private void writePayloadTooLargeResponse(HttpExchange exchange, Object payload)
      throws IOException {
    ScheduledFuture<?> closeDeadline = null;
    try {
      closeDeadline =
          readTimeoutScheduler.schedule(
              exchange::close, bodyReadTimeoutMillis, TimeUnit.MILLISECONDS);
    } catch (RejectedExecutionException ignored) {
      // The server is stopping; send the response and close the exchange.
    }
    try {
      writeJson(exchange, HTTP_PAYLOAD_TOO_LARGE, payload);
    } finally {
      try {
        exchange.close();
      } finally {
        if (closeDeadline != null) {
          closeDeadline.cancel(false);
        }
      }
    }
  }

  static void validateContentLength(Headers headers) {
    List<String> values = headers == null ? null : headers.get("Content-Length");
    if (values == null || values.isEmpty()) {
      return;
    }
    if (values.size() > 1) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Duplicate Content-Length header");
    }
    String raw = values.get(0);
    if (raw == null) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Invalid Content-Length header");
    }
    String trimmed = raw.trim();
    if (trimmed.isEmpty() || !isAsciiDigits(trimmed)) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Invalid Content-Length header");
    }
    long contentLength;
    try {
      contentLength = Long.parseLong(trimmed);
    } catch (NumberFormatException error) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Invalid Content-Length header", error);
    }
    if (contentLength > MAX_REQUEST_BODY_BYTES) {
      throw new JsonRpcError(
          HTTP_PAYLOAD_TOO_LARGE,
          null,
          JSONRPC_INVALID_REQUEST,
          "Request body exceeds maximum size of " + MAX_REQUEST_BODY_BYTES + " bytes");
    }
  }

  private static boolean isAsciiDigits(String value) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch < '0' || ch > '9') {
        return false;
      }
    }
    return true;
  }

  static String readBody(HttpExchange exchange) throws IOException {
    InputStream input = exchange.getRequestBody();
    // Guard len == 0 because jdk.httpserver's ChunkedInputStream reads the next chunk header on a
    // zero-length read after InputStream.readNBytes fills its final buffer.
    InputStream boundedView =
        new FilterInputStream(input) {
          @Override
          public int read(byte[] buf, int off, int len) throws IOException {
            return len == 0 ? 0 : in.read(buf, off, len);
          }
        };
    byte[] bytes = boundedView.readNBytes(MAX_REQUEST_BODY_BYTES + 1);
    if (bytes.length > MAX_REQUEST_BODY_BYTES) {
      throw new JsonRpcError(
          HTTP_PAYLOAD_TOO_LARGE,
          null,
          JSONRPC_INVALID_REQUEST,
          "Request body exceeds maximum size of " + MAX_REQUEST_BODY_BYTES + " bytes");
    }
    input.close();
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static void writeJsonRpcError(
      HttpExchange exchange, int httpStatus, Object id, int code, String message)
      throws IOException {
    writeJson(exchange, httpStatus, mcpErrorResponse(exchange, id, code, message, null));
  }

  private void writeJsonRpcErrorResponse(
      HttpExchange exchange,
      int httpStatus,
      Object id,
      int code,
      String message,
      boolean bodyRead)
      throws IOException {
    writeJsonResponse(
        exchange, httpStatus, mcpErrorResponse(exchange, id, code, message, null), bodyRead);
  }

  private static Map<String, Object> mcpErrorResponse(
      HttpExchange exchange, Object id, int code, String message, Map<String, Object> data) {
    Map<String, Object> response = data == null
        ? JsonRpc.errorResponse(id, code, message)
        : JsonRpc.errorResponse(id, code, message, data);
    if (!isRequestId(id)) {
      // The June error schema cannot express an unknown ID.
      // Follow the JSON-RPC null ID rule.
      if ("2025-06-18".equals(firstHeader(exchange, "MCP-Protocol-Version"))) {
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

  private void writeJsonResponse(
      HttpExchange exchange, int statusCode, Object payload, boolean bodyRead) throws IOException {
    if (bodyRead || !hasRequestBody(exchange) || isCompleteBodyBuffered(exchange)) {
      writeJson(exchange, statusCode, payload);
      return;
    }
    byte[] bytes = JsonUtil.toJson(payload, MAX_HTTP_RESPONSE_BYTES).getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    exchange.getResponseHeaders().set("Connection", "close");
    writeAndAbortUnread(exchange, statusCode, bytes);
  }

  private void writePlainResponse(
      HttpExchange exchange, int statusCode, String payload, boolean bodyRead) throws IOException {
    if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())
        || bodyRead
        || !hasRequestBody(exchange)
        || isCompleteBodyBuffered(exchange)) {
      writePlain(exchange, statusCode, payload);
      return;
    }
    byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.getResponseHeaders().set("Connection", "close");
    writeAndAbortUnread(exchange, statusCode, bytes);
  }

  private void writeAndAbortUnread(HttpExchange exchange, int statusCode, byte[] bytes)
      throws IOException {
    exchange.sendResponseHeaders(statusCode, bytes.length);
    OutputStream output = exchange.getResponseBody();
    output.write(bytes);
    output.flush();
    pauseBeforeUnreadClose();
    if (isCompleteBodyBuffered(exchange)) {
      output.close();
      return;
    }
    throw new UnreadRequestAbortedException();
  }

  private void pauseBeforeUnreadClose() {
    if (!closed.get()) {
      LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(50));
    }
  }

  private static boolean hasRequestBody(HttpExchange exchange) {
    if (firstHeader(exchange, "Transfer-Encoding") != null) {
      return true;
    }
    String contentLength = firstHeader(exchange, "Content-Length");
    if (contentLength == null) {
      return false;
    }
    try {
      return Long.parseLong(contentLength.trim()) > 0L;
    } catch (NumberFormatException invalid) {
      return true;
    }
  }

  private static void writeJson(HttpExchange exchange, int statusCode, Object payload)
      throws IOException {
    int contentLength = JsonUtil.utf8ByteLength(payload, MAX_HTTP_RESPONSE_BYTES);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    exchange.sendResponseHeaders(statusCode, contentLength);
    try (OutputStream output = exchange.getResponseBody()) {
      JsonUtil.writeUtf8(payload, output, contentLength);
    }
  }

  private static void writePlain(HttpExchange exchange, int statusCode, String payload)
      throws IOException {
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
      sendNoBody(exchange, statusCode);
      return;
    }
    byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private NetworkBinding.HostValidationResult validateHost(HttpExchange exchange) {
    List<String> hostHeaders = exchange.getRequestHeaders().get("Host");
    return NetworkBinding.validateHostHeader(
        hostHeaders, config.host(), server.getAddress().getPort(), loopbackListener);
  }

  private static void sendNoBody(HttpExchange exchange, int statusCode) throws IOException {
    exchange.sendResponseHeaders(statusCode, -1);
  }

  private void addCommonHeaders(HttpExchange exchange, String validatedOrigin) {
    if (validatedOrigin != null) {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", validatedOrigin);
      exchange.getResponseHeaders().set("Vary", "Origin");
    }
    exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    exchange
        .getResponseHeaders()
        .set(
            "Access-Control-Allow-Headers",
            "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Accept");
    exchange.getResponseHeaders().set("Access-Control-Expose-Headers", "MCP-Protocol-Version");
  }

  private record OriginValidation(boolean allowed, String origin) {
    static final OriginValidation ABSENT_ALLOWED = new OriginValidation(true, null);
    static final OriginValidation REJECTED = new OriginValidation(false, null);
  }

  private OriginValidation validateOrigin(HttpExchange exchange) {
    return validateOriginHeaders(
        exchange.getRequestHeaders().get("Origin"),
        normalizedConfiguredHost,
        configuredHostLiteral,
        config.allowedOrigins());
  }

  static boolean isAllowedOrigin(List<String> originHeaders, String configuredHost) {
    return isAllowedOrigin(originHeaders, configuredHost, null);
  }

  static boolean isAllowedOrigin(List<String> originHeaders, Set<String> allowedOrigins) {
    return isAllowedOrigin(
        originHeaders, "127.0.0.1", Objects.requireNonNull(allowedOrigins, "allowedOrigins"));
  }

  static boolean isAllowedOrigin(
      List<String> originHeaders, String configuredHost, Set<String> allowedOrigins) {
    String normalizedConfigHost =
        normalizeHost(Objects.requireNonNull(configuredHost, "configuredHost"));
    return validateOriginHeaders(
            originHeaders,
            normalizedConfigHost,
            parseIpLiteral(normalizedConfigHost),
            allowedOrigins)
        .allowed();
  }

  private static OriginValidation validateOriginHeaders(
      List<String> values,
      String normalizedConfigHost,
      InetAddress configHostLiteral,
      Set<String> allowedOriginsOverride) {
    if (values == null || values.isEmpty()) {
      return OriginValidation.ABSENT_ALLOWED;
    }
    if (values.size() != 1) {
      return OriginValidation.REJECTED;
    }
    String rawOrigin = values.get(0);
    if (rawOrigin == null) {
      return OriginValidation.REJECTED;
    }
    String origin = rawOrigin.trim();
    if (allowedOriginsOverride != null) {
      if (allowedOriginsOverride.isEmpty()) {
        return OriginValidation.REJECTED;
      }
      String normalized = McpConfig.tryNormalizeOrigin(origin);
      if (normalized == null || !allowedOriginsOverride.contains(normalized)) {
        return OriginValidation.REJECTED;
      }
      return new OriginValidation(true, origin);
    }

    if (origin.isEmpty()
        || "null".equalsIgnoreCase(origin)
        || origin.indexOf(',') >= 0
        || origin.indexOf('?') >= 0
        || origin.indexOf('#') >= 0) {
      return OriginValidation.REJECTED;
    }

    final URI uri;
    try {
      uri = URI.create(origin);
    } catch (IllegalArgumentException invalidOrigin) {
      return OriginValidation.REJECTED;
    }

    String scheme = uri.getScheme();
    if (scheme == null
        || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
        || uri.isOpaque()) {
      return OriginValidation.REJECTED;
    }

    String rawAuthority = uri.getRawAuthority();
    if (rawAuthority == null
        || rawAuthority.isEmpty()
        || uri.getRawUserInfo() != null
        || uri.getUserInfo() != null
        || rawAuthority.indexOf('@') >= 0
        || rawAuthority.endsWith(":")) {
      return OriginValidation.REJECTED;
    }

    int port = uri.getPort();
    if (port != -1 && (port < 1 || port > 65535)) {
      return OriginValidation.REJECTED;
    }

    String rawPath = uri.getRawPath();
    if ((rawPath != null && !rawPath.isEmpty())
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      return OriginValidation.REJECTED;
    }

    String rawHost = uri.getHost();
    if (rawHost == null || rawHost.isBlank()) {
      return OriginValidation.REJECTED;
    }

    String normalizedOriginHost = normalizeHost(rawHost);
    if (normalizedOriginHost.isEmpty()) {
      return OriginValidation.REJECTED;
    }

    InetAddress originLiteral = parseIpLiteral(normalizedOriginHost);
    if (originLiteral != null) {
      if (!originLiteral.isAnyLocalAddress()
          && (originLiteral.isLoopbackAddress() || originLiteral.equals(configHostLiteral))) {
        return new OriginValidation(true, origin);
      }
      return OriginValidation.REJECTED;
    }

    if ("localhost".equals(normalizedOriginHost)
        || normalizedOriginHost.equals(normalizedConfigHost)) {
      return new OriginValidation(true, origin);
    }

    return OriginValidation.REJECTED;
  }

  static String normalizeHost(String host) {
    return NetworkBinding.normalizeHost(host);
  }

  static InetAddress parseIpLiteral(String literal) {
    return NetworkBinding.parseIpLiteral(literal);
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

  static final class JsonRpcError extends RuntimeException {
    @Serial
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

  private static String getQueryParameter(URI uri, String name) {
    String query = uri.getRawQuery();
    if (query == null || query.isBlank()) {
      return null;
    }
    for (String pair : query.split("&")) {
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

  private static final class BodyReadTimeoutException extends IOException {
    @Serial
    private static final long serialVersionUID = 1L;

    BodyReadTimeoutException(Throwable cause) {
      super("Request body read timed out", cause);
    }
  }

  private static final class UnreadRequestAbortedException extends IOException {
    @Serial
    private static final long serialVersionUID = 1L;

    UnreadRequestAbortedException() {
      super("Closing exchange without draining unread request body");
    }
  }

  static final class SseSession implements AutoCloseable {
    private final HttpExchange exchange;
    private final OutputStream output;
    private final AtomicBoolean active = new AtomicBoolean(true);
    private final AtomicBoolean streamClosed = new AtomicBoolean(false);
    private final CountDownLatch closeLatch = new CountDownLatch(1);
    private final ReentrantLock writeLock = new ReentrantLock();

    SseSession(HttpExchange exchange) throws IOException {
      this.exchange = exchange;
      exchange.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
      exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-transform");
      exchange.getResponseHeaders().set("Connection", "keep-alive");
      exchange.getResponseHeaders().set("X-Accel-Buffering", "no");
      exchange.sendResponseHeaders(200, 0);
      this.output = exchange.getResponseBody();
    }

    void sendEvent(String event, String data) throws IOException {
      writeLock.lock();
      try {
        if (!active.get()) {
          return;
        }
        StringBuilder sb = new StringBuilder();
        if (event != null && !event.isBlank()) {
          sb.append("event: ").append(event).append("\n");
        }
        for (String line : data.split("\r?\n")) {
          sb.append("data: ").append(line).append("\n");
        }
        sb.append("\n");
        output.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        output.flush();
      } catch (IOException error) {
        close();
        throw error;
      } finally {
        writeLock.unlock();
      }
    }

    void sendComment(String comment) throws IOException {
      writeLock.lock();
      try {
        if (!active.get()) {
          return;
        }
        String payload = ": " + comment + "\n\n";
        output.write(payload.getBytes(StandardCharsets.UTF_8));
        output.flush();
      } catch (IOException error) {
        close();
        throw error;
      } finally {
        writeLock.unlock();
      }
    }

    boolean awaitClose(long timeout, TimeUnit unit) throws InterruptedException {
      return closeLatch.await(timeout, unit);
    }

    @Override
    public void close() {
      active.set(false);
      closeLatch.countDown();
      if (writeLock.tryLock()) {
        try {
          closeStream();
        } finally {
          writeLock.unlock();
        }
      }
    }

    void closeAndAwaitStream() {
      active.set(false);
      closeLatch.countDown();
      boolean interrupted = Thread.interrupted();
      writeLock.lock();
      try {
        closeStream();
      } finally {
        writeLock.unlock();
        if (interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }

    private void closeStream() {
      if (!streamClosed.compareAndSet(false, true)) {
        return;
      }
      try {
        output.close();
      } catch (IOException ignored) {}
      try {
        exchange.close();
      } catch (Exception ignored) {}
    }

    boolean isActive() {
      return active.get();
    }
  }
}
