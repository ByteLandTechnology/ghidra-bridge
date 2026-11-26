package app.byteland.ghidra.agent;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Dispatches API requests with concurrent shared reads, fair exclusive writes, and graceful
 * shutdown barriers.
 */
public final class AgentDispatcher implements AutoCloseable {
  private final String sessionId;
  private final String programName;
  private final BridgeServices services;
  private final ApiRegistry apiRegistry;
  private final DispatchBarrier dispatchBarrier = new DispatchBarrier();
  private volatile boolean shuttingDown;

  /**
   * Creates a dispatcher backed by the given bridge services and session configuration.
   *
   * @param services domain services for the active program
   * @param config runtime session configuration
   */
  public AgentDispatcher(BridgeServices services, AgentConfig config) {
    this(
        Objects.requireNonNull(services, "services"),
        Objects.requireNonNull(config, "config").sessionId());
  }

  /**
   * Creates a dispatcher backed by the given bridge services and session identifier.
   *
   * @param services domain services for the active program
   * @param sessionId non-blank runtime session identifier
   */
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

  /**
   * Dispatches one API method call under the shared-read or exclusive-write lock.
   *
   * @param method dotted API method name
   * @param params decoded request parameters
   * @return serialized response payload
   * @throws Exception if validation or method execution fails
   */
  public Object dispatch(String method, Map<String, Object> params) throws Exception {
    return dispatchBarrier.run(
        () -> {
          ApiRegistry.PreparedDispatch prepared = apiRegistry.prepareDispatch(method, params);
          Object rawResponse =
              prepared.readOnly()
                  ? dispatchBarrier.runRead(prepared::execute)
                  : dispatchBarrier.runWrite(prepared::execute);
          return prepared.encodeResponse(rawResponse);
        });
  }

  /**
   * Runs a lifecycle action under the fair write lock while the dispatcher is open.
   *
   * @param action exclusive action to run
   */
  public void runExclusive(Runnable action) {
    Objects.requireNonNull(action, "action");
    try {
      dispatchBarrier.run(
          () ->
              dispatchBarrier.runWrite(
                  () -> {
                    action.run();
                    return null;
                  }));
    } catch (RuntimeException error) {
      throw error;
    } catch (Exception error) {
      throw new IllegalStateException("Exclusive dispatcher action failed", error);
    }
  }

  DispatchBarrier barrier() {
    return dispatchBarrier;
  }

  /**
   * Returns the registered API method catalog.
   *
   * @return API method catalog
   */
  public ApiCatalog methodCatalog() {
    return apiRegistry.methodCatalog();
  }

  /**
   * Reports whether session shutdown has started.
   *
   * @return {@code true} if shutdown was requested
   */
  public boolean isShuttingDown() {
    return shuttingDown;
  }

  /**
   * Returns the name of the active Ghidra program.
   *
   * @return program name
   */
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
