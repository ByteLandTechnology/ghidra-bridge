package app.byteland.ghidra.agent;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.ApiMethod;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Dispatches API requests to the registry, runs program operations one at a time, and blocks new
 * requests during shutdown.
 */
public final class AgentDispatcher implements AutoCloseable {
  private static final Set<String> LOCK_FREE_METHODS =
      Set.of("interface.get", "session.get", "analysis.get");

  private final String sessionId;
  private final String programName;
  private final BridgeServices services;
  private final ApiRegistry apiRegistry;
  private final DispatchBarrier dispatchBarrier = new DispatchBarrier();
  private final ReentrantLock sequenceLock = new ReentrantLock(true);
  private volatile boolean shuttingDown;

  public AgentDispatcher(BridgeServices services, AgentConfig config) {
    this(
        Objects.requireNonNull(services, "services"),
        Objects.requireNonNull(config, "config").sessionId());
  }

  public AgentDispatcher(BridgeServices services, String sessionId) {
    this.services = Objects.requireNonNull(services, "services");
    String normalizedSessionId = AgentConfig.optionalText(sessionId);
    if (normalizedSessionId == null) {
      throw new IllegalArgumentException("sessionId is required");
    }
    this.sessionId = normalizedSessionId;
    this.programName = services.programName();
    this.apiRegistry =
        new ApiRegistry(services, this.sessionId, this::sessionInfo, this::markShuttingDown);
  }

  @Override
  public void close() {
    if (!dispatchBarrier.closeAndAwait()) return;
    services.close();
  }

  public Object dispatch(String method, Map<String, Object> params) throws Exception {
    return dispatchBarrier.run(
        () -> {
          if (method == null || method.isBlank()) {
            throw ApiException.badRequest("missing_method", "method is required", "/method");
          }
          ApiMethod<Map<String, Object>, Object> apiMethod = apiRegistry.requireMethod(method);
          Map<String, Object> decoded = apiMethod.decodeRequest(params);
          Object response = executeMethod(apiMethod, decoded);
          return apiMethod.encodeResponse(decoded, response);
        });
  }

  boolean isSequenceLocked() {
    return sequenceLock.isLocked();
  }

  boolean isSequenceLockedByCurrentThread() {
    return sequenceLock.isHeldByCurrentThread();
  }

  private Object executeMethod(
      ApiMethod<Map<String, Object>, Object> apiMethod, Map<String, Object> decoded)
      throws Exception {
    if (LOCK_FREE_METHODS.contains(apiMethod.name())) {
      return apiRegistry.executeDecoded(apiMethod, decoded);
    }
    sequenceLock.lock();
    try {
      return apiRegistry.executeDecoded(apiMethod, decoded);
    } finally {
      sequenceLock.unlock();
    }
  }

  public ApiCatalog methodCatalog() {
    return apiRegistry.methodCatalog();
  }

  public boolean isShuttingDown() {
    return shuttingDown;
  }

  public String getProgramName() {
    return programName;
  }

  private Map<String, Object> sessionInfo() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("id", sessionId);
    info.put("status", shuttingDown ? "shutting_down" : "active");
    info.put("program_name", programName);
    return info;
  }

  private void markShuttingDown() {
    shuttingDown = true;
  }
}
