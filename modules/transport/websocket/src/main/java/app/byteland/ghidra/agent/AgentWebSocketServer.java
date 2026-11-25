package app.byteland.ghidra.agent;

import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Embedded WebSocket server for inbound JSON-RPC 2.0 connections. */
public final class AgentWebSocketServer implements AutoCloseable {
  public static final String DEFAULT_PATH = "/ws/agent";
  private static final int SERVER_SHUTDOWN_CLOSE_CODE = 1001;
  static final Duration DEFAULT_HANDSHAKE_TIMEOUT = Duration.ofSeconds(10);
  static final int DEFAULT_MAX_PENDING_SOCKETS = 16;

  private final AgentConfig config;
  private final Handler handler;
  private final Duration handshakeTimeout;
  private final AtomicBoolean running = new AtomicBoolean(false);
  private final AtomicReference<AgentServerConnection> activeConnection = new AtomicReference<>();
  private final PendingSockets pendingSockets;
  private ServerSocket serverSocket;

  public AgentWebSocketServer(AgentConfig config, Handler handler) {
    this(config, handler, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_PENDING_SOCKETS);
  }

  AgentWebSocketServer(
      AgentConfig config, Handler handler, Duration handshakeTimeout, int maxPendingSockets) {
    this.config = Objects.requireNonNull(config, "config");
    this.handler = Objects.requireNonNull(handler, "handler");
    Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
    if (handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
      throw new IllegalArgumentException("handshakeTimeout must be positive");
    }
    if (maxPendingSockets < 1) {
      throw new IllegalArgumentException("maxPendingSockets must be positive");
    }
    this.handshakeTimeout = handshakeTimeout;
    this.pendingSockets = new PendingSockets(running, maxPendingSockets);
  }

  public void start() throws IOException {
    if (!running.compareAndSet(false, true)) {
      return;
    }
    ServerSocket socket = new ServerSocket();
    try {
      socket.bind(new InetSocketAddress(config.host(), config.port()));
      AgentWebSocketConnectionRunner connectionRunner =
          new AgentWebSocketConnectionRunner(
              config, handler, running, activeConnection, pendingSockets, handshakeTimeout);
      AgentWebSocketAcceptor acceptor =
          new AgentWebSocketAcceptor(socket, handler, running, pendingSockets, connectionRunner);
      Thread thread = new Thread(acceptor, "agent-ws-server");
      thread.setDaemon(true);
      serverSocket = socket;
      thread.start();
    } catch (BindException bindFailure) {
      running.set(false);
      BindException friendly =
          new BindException(
              "WebSocket endpoint "
                  + config.serverEndpoint()
                  + " is already in use. Stop the existing Bridge/GhidraMcp script, close the old"
                  + " Ghidra session, or pass a different port value.");
      friendly.initCause(bindFailure);
      closeAfterFailedStart(socket, friendly);
      throw friendly;
    } catch (IOException | RuntimeException startFailure) {
      running.set(false);
      closeAfterFailedStart(socket, startFailure);
      throw startFailure;
    }
  }

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
  public void close() {
    running.set(false);
    AgentServerConnection connection = activeConnection.getAndSet(null);
    if (connection != null) {
      try {
        connection.close(SERVER_SHUTDOWN_CLOSE_CODE, "server shutdown");
      } catch (RuntimeException failure) {
        handler.onConnectionError(connection, failure);
      }
    }
    for (Socket pending : pendingSockets.drain()) {
      if (!pending.isClosed()) {
        try {
          pending.close();
        } catch (IOException failure) {
          handler.onConnectionError(null, failure);
        }
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

  static final class PendingSockets {
    private final Object lock = new Object();
    private final AtomicBoolean running;
    private final int maxSockets;
    private final Set<Socket> sockets = new LinkedHashSet<>();

    PendingSockets(AtomicBoolean running, int maxSockets) {
      this.running = running;
      this.maxSockets = maxSockets;
    }

    boolean tryAdd(Socket socket) {
      synchronized (lock) {
        if (!running.get() || sockets.size() >= maxSockets) {
          return false;
        }
        return sockets.add(socket);
      }
    }

    void remove(Socket socket) {
      synchronized (lock) {
        sockets.remove(socket);
      }
    }

    List<Socket> drain() {
      synchronized (lock) {
        List<Socket> snapshot = List.copyOf(sockets);
        sockets.clear();
        return snapshot;
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
