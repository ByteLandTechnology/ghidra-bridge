package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Embedded WebSocket server for inbound JSON-RPC 2.0 connections.
 */
public final class AgentWebSocketServer implements AutoCloseable {
  public static final String DEFAULT_PATH = "/ws/agent";
  private static final int SERVER_SHUTDOWN_CLOSE_CODE = 1001;
  private static final int MAX_LOOPBACK_PORT_ATTEMPTS = 64;
  static final Object RESERVED_CONNECTION_SLOT = new Object();

  private final AgentConfig config;
  private final Handler handler;
  private final boolean allowLoopbackPortFallback;
  private final AtomicBoolean running = new AtomicBoolean(false);
  private final AtomicReference<Object> activeConnection = new AtomicReference<>();
  private final AtomicReference<Socket> pendingSocket = new AtomicReference<>();
  private volatile AgentConfig boundConfig;
  private ServerSocket serverSocket;

  public AgentWebSocketServer(AgentConfig config, Handler handler) {
    this(config, handler, false);
  }

  public AgentWebSocketServer(
      AgentConfig config, Handler handler, boolean allowLoopbackPortFallback) {
    this.config = config;
    this.handler = handler;
    this.allowLoopbackPortFallback = allowLoopbackPortFallback;
    this.boundConfig = config;
  }

  public int port() {
    return boundConfig.port();
  }

  public String listenUri() {
    return "ws://" + boundConfig.host() + ":" + boundConfig.port() + boundConfig.path();
  }

  @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CloseResource"})
  public void start() throws IOException {
    if (!running.compareAndSet(false, true)) {
      return;
    }
    ServerSocket socket = null;
    try {
      socket = bindServerSocket();
      int localPort = socket.getLocalPort();
      AgentConfig effectiveConfig =
          localPort == config.port()
              ? config
              : new AgentConfig(
                  null,
                  config.host(),
                  localPort,
                  config.path(),
                  config.token(),
                  config.sessionId(),
                  null);
      boundConfig = effectiveConfig;
      AgentWebSocketConnectionRunner connectionRunner =
          new AgentWebSocketConnectionRunner(
              effectiveConfig, handler, running, activeConnection, pendingSocket);
      AgentWebSocketAcceptor acceptor =
          new AgentWebSocketAcceptor(
              socket, handler, running, activeConnection, pendingSocket, connectionRunner);
      Thread thread = new Thread(acceptor, "agent-ws-server");
      thread.setDaemon(true);
      serverSocket = socket;
      thread.start();
    } catch (IOException | RuntimeException startFailure) {
      running.set(false);
      if (socket != null) {
        closeAfterFailedStart(socket, startFailure);
      }
      throw startFailure;
    }
  }

  @SuppressWarnings("PMD.CloseResource")
  private ServerSocket bindServerSocket() throws IOException {
    int basePort = config.port();
    int maxAttempts =
        allowLoopbackPortFallback && NetworkBinding.isLoopback(config.host())
            ? Math.min(MAX_LOOPBACK_PORT_ATTEMPTS, 65535 - basePort + 1)
            : 1;
    BindException lastBindError = null;
    for (int offset = 0; offset < maxAttempts; offset++) {
      ServerSocket candidate = new ServerSocket();
      try {
        candidate.bind(new InetSocketAddress(config.host(), basePort + offset));
        return candidate;
      } catch (BindException bindError) {
        lastBindError = bindError;
        closeAfterFailedStart(candidate, bindError);
      } catch (IOException | RuntimeException otherError) {
        closeAfterFailedStart(candidate, otherError);
        throw otherError;
      }
    }
    throw lastBindError != null
        ? lastBindError
        : new BindException("Address already in use: " + config.host() + ":" + basePort);
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  private static void closeAfterFailedStart(ServerSocket socket, Throwable startFailure) {
    try {
      socket.close();
    } catch (IOException closeFailure) {
      if (closeFailure != startFailure) {
        startFailure.addSuppressed(closeFailure);
      }
    }
  }

  @Override
  @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CloseResource"})
  public void close() {
    running.set(false);
    Object slot = activeConnection.getAndSet(null);
    if (slot instanceof AgentServerConnection connection) {
      try {
        connection.close(SERVER_SHUTDOWN_CLOSE_CODE, "server shutdown");
      } catch (RuntimeException failure) {
        handler.onConnectionError(connection, failure);
      }
    }
    Socket pending = pendingSocket.getAndSet(null);
    if (pending != null && !pending.isClosed()) {
      try {
        pending.close();
      } catch (IOException failure) {
        handler.onConnectionError(null, failure);
      }
    }
    ServerSocket socket = serverSocket;
    if (socket != null && !socket.isClosed()) {
      try {
        socket.close();
      } catch (IOException failure) {
        handler.onServerError(failure);
      }
    }
  }

  public interface Connection {
    void sendText(String message);

    void close(int statusCode, String reason);
  }

  public interface Handler {
    void onOpen(Connection connection);

    void onText(Connection connection, String message);

    void onClose(Connection connection, int statusCode, String reason);

    void onConnectionError(Connection connection, Throwable error);

    void onServerError(Throwable error);
  }
}
