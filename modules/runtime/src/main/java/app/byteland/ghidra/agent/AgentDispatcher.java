package app.byteland.ghidra.agent;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Dispatches API requests to the registry one at a time and blocks new requests during shutdown.
 */
public final class AgentDispatcher implements AutoCloseable {
  private final AgentConfig config;
  private final String programName;
  private final BridgeServices services;
  private final ApiRegistry apiRegistry;
  private final DispatchBarrier dispatchBarrier = new DispatchBarrier();
  private final Object sequenceLock = new Object();
  private volatile boolean shuttingDown;

  public AgentDispatcher(BridgeServices services, AgentConfig config) {
    Objects.requireNonNull(services, "services");
    this.config = Objects.requireNonNull(config, "config");
    this.services = services;
    this.programName = services.programName();
    this.apiRegistry =
        new ApiRegistry(services, config.sessionId(), this::sessionInfo, this::markShuttingDown);
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
          synchronized (sequenceLock) {
            return apiRegistry.dispatch(method, params);
          }
        });
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
    info.put("id", config.sessionId());
    info.put("status", shuttingDown ? "shutting_down" : "active");
    info.put("program_name", programName);
    return info;
  }

  private void markShuttingDown() {
    shuttingDown = true;
  }
}
