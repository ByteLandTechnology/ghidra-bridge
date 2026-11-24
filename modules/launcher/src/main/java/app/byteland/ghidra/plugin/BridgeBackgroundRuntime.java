package app.byteland.ghidra.plugin;

import app.byteland.ghidra.agent.AgentClient;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.mcp.McpHttpServer;
import app.byteland.ghidra.plugin.DaemonAttachDiscovery.AttachTarget;
import app.byteland.ghidra.plugin.PluginSettings.TransportMode;
import app.byteland.ghidra.service.BridgeServices;
import ghidra.program.model.listing.Program;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Manages the background local listener and optional outbound {@code ghidra-mcp} connection.
 */
public final class BridgeBackgroundRuntime implements AutoCloseable {
  private static final System.Logger LOGGER =
      System.getLogger(BridgeBackgroundRuntime.class.getName());
  private static final String GUI_SESSION_ID = "ghidra-bridge-gui";
  private static final long ATTACH_POLL_SECONDS = 3L;
  private static final long STARTUP_WAIT_SECONDS = 5L;

  private final BridgeServices services;
  private final Supplier<Program> activeProgramSupplier;
  private final Supplier<Optional<AttachTarget>> attachDiscovery;
  private final Consumer<String> statusConsumer;
  private final ScheduledExecutorService controlExecutor;
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final AtomicReference<PluginSettings> settingsRef =
      new AtomicReference<>(PluginSettings.defaults());

  private LocalListenerHandle localListener;
  private OutboundAttachHandle outboundAttach;
  private volatile String localSummary;
  private volatile String localEndpoint;
  private volatile int localPort;
  private volatile boolean attachedToDaemon;

  public BridgeBackgroundRuntime(
      BridgeServices services,
      Supplier<Program> activeProgramSupplier,
      Supplier<Optional<AttachTarget>> attachDiscovery,
      Consumer<String> statusConsumer) {
    this.services = Objects.requireNonNull(services, "services");
    this.activeProgramSupplier =
        Objects.requireNonNull(activeProgramSupplier, "activeProgramSupplier");
    this.attachDiscovery = Objects.requireNonNull(attachDiscovery, "attachDiscovery");
    this.statusConsumer = Objects.requireNonNull(statusConsumer, "statusConsumer");
    this.controlExecutor =
        Executors.newSingleThreadScheduledExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "ghidra-bridge-plugin-ctl");
              thread.setDaemon(true);
              return thread;
            });
    this.controlExecutor.scheduleWithFixedDelay(
        this::pollAutoAttach, ATTACH_POLL_SECONDS, ATTACH_POLL_SECONDS, TimeUnit.SECONDS);
    publishStatus("Bridge: idle (no program)");
  }

  public int localPort() {
    return localPort;
  }

  public String localEndpoint() {
    return localEndpoint;
  }

  public boolean isAttachedToDaemon() {
    return attachedToDaemon;
  }

  public void applySettings(PluginSettings newSettings, boolean hasOpenPrograms) {
    Objects.requireNonNull(newSettings, "newSettings");
    PluginSettings previous = settingsRef.getAndSet(newSettings);
    submitControl(
        () -> {
          boolean transportChanged =
              previous.transportMode() != newSettings.transportMode()
                  || !previous.host().equals(newSettings.host())
                  || previous.port() != newSettings.port()
                  || !previous.path().equals(newSettings.path())
                  || !previous.toolPrefix().equals(newSettings.toolPrefix());
          if (localListener != null && transportChanged) {
            stopLocalListenerInternal();
            startLocalListenerInternal(newSettings);
          } else if (localListener == null && newSettings.autoStart() && hasOpenPrograms) {
            startLocalListenerInternal(newSettings);
          }

          if (!newSettings.autoAttachDaemon()) {
            stopOutboundAttachInternal();
          } else {
            reconcileOutboundAttach(false);
          }
          refreshStatus();
        });
  }

  public void onProgramActivated(Program program) {
    if (program == null) {
      return;
    }
    submitControl(
        () -> {
          PluginSettings settings = settingsRef.get();
          if (localListener == null && settings.autoStart()) {
            startLocalListenerInternal(settings);
          }
          if (settings.autoAttachDaemon()) {
            reconcileOutboundAttach(false);
          }
          refreshStatus();
        });
  }

  public void onProgramDeactivated() {
    submitControl(this::refreshStatus);
  }

  public void onAllProgramsClosed() {
    submitControl(
        () -> {
          stopOutboundAttachInternal();
          stopLocalListenerInternal();
          publishStatus("Bridge: idle (no program)");
        });
  }

  public void startOrRestartManual() {
    submitControl(
        () -> {
          stopLocalListenerInternal();
          startLocalListenerInternal(settingsRef.get());
          if (settingsRef.get().autoAttachDaemon()) {
            reconcileOutboundAttach(false);
          }
          refreshStatus();
        });
  }

  public void stopManual() {
    submitControl(
        () -> {
          stopOutboundAttachInternal();
          stopLocalListenerInternal();
          publishStatus("Bridge: stopped");
        });
  }

  public void attachNow() {
    submitControl(
        () -> {
          reconcileOutboundAttach(true);
          refreshStatus();
        });
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    try {
      controlExecutor
          .submit(
              () -> {
                stopOutboundAttachInternal();
                stopLocalListenerInternal();
              })
          .get(STARTUP_WAIT_SECONDS, TimeUnit.SECONDS);
    } catch (Exception ignored) {
      // Proceed with executor shutdown.
    } finally {
      controlExecutor.shutdownNow();
    }
  }

  private void submitControl(Runnable task) {
    if (closed.get()) {
      return;
    }
    controlExecutor.execute(
        () -> {
          if (closed.get()) {
            return;
          }
          try {
            task.run();
          } catch (RuntimeException failure) {
            LOGGER.log(System.Logger.Level.WARNING, "Ghidra Bridge background task failed", failure);
          }
        });
  }

  private void pollAutoAttach() {
    if (closed.get() || !settingsRef.get().autoAttachDaemon()) {
      return;
    }
    reconcileOutboundAttach(false);
    refreshStatus();
  }

  private void startLocalListenerInternal(PluginSettings settings) {
    try {
      if (settings.transportMode() == TransportMode.MCP_HTTP) {
        McpConfig mcpConfig =
            new McpConfig(
                settings.host(),
                settings.port(),
                settings.path(),
                null,
                GUI_SESSION_ID,
                settings.toolPrefix());
        AgentDispatcher dispatcher = new AgentDispatcher(services, GUI_SESSION_ID, false);
        McpHttpServer server = new McpHttpServer(mcpConfig, dispatcher, ignored -> {}, true);
        server.start();
        localPort = server.port();
        localEndpoint = server.endpoint();
        localSummary = "MCP :" + server.port();
        localListener =
            () -> {
              server.close();
              dispatcher.close();
            };
      } else {
        AgentConfig wsConfig =
            new AgentConfig(
                null,
                settings.host(),
                settings.port(),
                settings.path(),
                null,
                GUI_SESSION_ID,
                null);
        AgentDispatcher dispatcher = new AgentDispatcher(services, wsConfig, false);
        CountDownLatch startedLatch = new CountDownLatch(1);
        AtomicInteger boundPort = new AtomicInteger(settings.port());
        AtomicReference<String> boundUri = new AtomicReference<>();
        AtomicReference<Exception> startupError = new AtomicReference<>();
        AtomicBoolean stopRequested = new AtomicBoolean(false);
        AgentClient client =
            new AgentClient(
                wsConfig,
                dispatcher,
                new AgentClient.LifecycleListener() {
                  @Override
                  public void onListening(String listenUri, int port) {
                    boundPort.set(port);
                    boundUri.set(listenUri);
                    startedLatch.countDown();
                  }
                },
                true);
        Thread serverThread =
            new Thread(
                () -> {
                  try {
                    client.connect(stopRequested::get);
                  } catch (Exception failure) {
                    startupError.set(failure);
                    startedLatch.countDown();
                  }
                },
                "ghidra-bridge-ws-listener");
        serverThread.setDaemon(true);
        serverThread.start();
        boolean started = startedLatch.await(STARTUP_WAIT_SECONDS, TimeUnit.SECONDS);
        if (!started || startupError.get() != null) {
          stopRequested.set(true);
          client.disconnect();
          dispatcher.close();
          Exception cause = startupError.get();
          throw cause != null ? cause : new IOException("Timed out starting WebSocket listener");
        }
        localPort = boundPort.get();
        localEndpoint = boundUri.get();
        localSummary = "WS :" + boundPort.get();
        localListener =
            () -> {
              stopRequested.set(true);
              client.disconnect();
              dispatcher.close();
            };
      }
    } catch (Exception failure) {
      localPort = 0;
      localEndpoint = null;
      localSummary = "error";
      LOGGER.log(System.Logger.Level.WARNING, "Failed to start local Ghidra Bridge listener", failure);
    }
  }

  private void stopLocalListenerInternal() {
    LocalListenerHandle handle = localListener;
    localListener = null;
    localPort = 0;
    localEndpoint = null;
    localSummary = null;
    if (handle != null) {
      handle.close();
    }
  }

  private void reconcileOutboundAttach(boolean forceReconnect) {
    Program activeProgram = activeProgramSupplier.get();
    if (activeProgram == null) {
      stopOutboundAttachInternal();
      return;
    }

    Optional<AttachTarget> targetOpt = attachDiscovery.get();
    if (targetOpt.isEmpty()) {
      stopOutboundAttachInternal();
      return;
    }
    AttachTarget target = targetOpt.get();
    String sessionId = DaemonAttachDiscovery.computeProgramSessionId(activeProgram);

    OutboundAttachHandle existing = outboundAttach;
    if (!forceReconnect
        && existing != null
        && existing.isAlive()
        && existing.matches(target.wsUrl(), sessionId)) {
      return;
    }

    stopOutboundAttachInternal();
    AgentConfig attachConfig =
        new AgentConfig(target.wsUrl(), null, null, null, target.token(), sessionId, null);
    AgentDispatcher dispatcher = new AgentDispatcher(services, attachConfig, false);
    AtomicBoolean stopRequested = new AtomicBoolean(false);
    AtomicBoolean alive = new AtomicBoolean(true);
    AgentClient client =
        new AgentClient(
            attachConfig,
            dispatcher,
            new AgentClient.LifecycleListener() {
              @Override
              public void onConnected() {
                attachedToDaemon = true;
                submitControl(BridgeBackgroundRuntime.this::refreshStatus);
              }
            },
            false);
    Thread attachThread =
        new Thread(
            () -> {
              try {
                client.connect(stopRequested::get);
              } catch (Exception ignored) {
                // Transient daemon restarts are retried by the background poller.
              } finally {
                alive.set(false);
                attachedToDaemon = false;
                dispatcher.close();
                submitControl(this::refreshStatus);
              }
            },
            "ghidra-bridge-daemon-attach");
    attachThread.setDaemon(true);
    outboundAttach =
        new OutboundAttachHandle(
            target.wsUrl(), sessionId, alive, stopRequested, client, dispatcher);
    attachThread.start();
  }

  private void stopOutboundAttachInternal() {
    OutboundAttachHandle handle = outboundAttach;
    outboundAttach = null;
    attachedToDaemon = false;
    if (handle != null) {
      handle.close();
    }
  }

  private void refreshStatus() {
    Program program = activeProgramSupplier.get();
    if (localSummary == null) {
      if (attachedToDaemon) {
        publishStatus("Bridge: attached");
      } else if (program == null) {
        publishStatus("Bridge: idle (no program)");
      } else {
        publishStatus("Bridge: stopped");
      }
      return;
    }
    if ("error".equals(localSummary)) {
      publishStatus("Bridge: error");
      return;
    }
    String suffix = attachedToDaemon ? " (attached)" : "";
    publishStatus("Bridge: " + localSummary + suffix);
  }

  private void publishStatus(String text) {
    statusConsumer.accept(text);
  }

  @FunctionalInterface
  private interface LocalListenerHandle {
    void close();
  }

  private record OutboundAttachHandle(
      String wsUrl,
      String sessionId,
      AtomicBoolean alive,
      AtomicBoolean stopRequested,
      AgentClient client,
      AgentDispatcher dispatcher) {
    boolean isAlive() {
      return alive.get();
    }

    boolean matches(String candidateUrl, String candidateSessionId) {
      return wsUrl.equals(candidateUrl) && sessionId.equals(candidateSessionId);
    }

    void close() {
      stopRequested.set(true);
      alive.set(false);
      client.disconnect();
      dispatcher.close();
    }
  }
}
