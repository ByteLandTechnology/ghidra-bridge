package app.byteland.ghidra.agent;

import java.io.IOException;
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

/**
 * Embedded WebSocket server for inbound JSON-RPC 2.0 connections.
 */
public final class AgentWebSocketServer implements AutoCloseable {
  /** Default WebSocket request path accepted by the embedded server. */
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

  /**
   * Creates an embedded WebSocket server for the given session configuration and event handler.
   *
   * @param config server bind, path, and token configuration
   * @param handler callback handler for WebSocket connection events
   */
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

  /**
   * Binds the server socket and starts the background accept loop.
   *
   * @throws IOException if binding the server socket fails
   */
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
    } catch (IOException | RuntimeException startFailure) {
      running.set(false);
      closeAfterFailedStart(socket, startFailure);
      throw startFailure;
    }
  }

  @SuppressWarnings("ReferenceEquality")
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

  /** Active WebSocket client connection accepted by {@link AgentWebSocketServer}. */
  public interface Connection {
    /**
     * Sends a UTF-8 text frame to the connected peer.
     *
     * @param message text payload to send
     */
    void sendText(String message);

    /**
     * Sends a WebSocket close frame and closes the underlying socket.
     *
     * @param statusCode WebSocket close status code
     * @param reason human-readable close reason
     */
    void close(int statusCode, String reason);
  }

  /** Callback interface receiving connection and server events from {@link AgentWebSocketServer}. */
  public interface Handler {
    /**
     * Invoked after a client completes the WebSocket upgrade handshake.
     *
     * @param connection accepted client connection
     */
    void onOpen(Connection connection);

    /**
     * Invoked when a complete UTF-8 text message is received from a client.
     *
     * @param connection source client connection
     * @param message decoded text payload
     */
    void onText(Connection connection, String message);

    /**
     * Invoked when a client connection closes.
     *
     * @param connection closed client connection
     * @param statusCode WebSocket close status code
     * @param reason close reason string
     */
    void onClose(Connection connection, int statusCode, String reason);

    /**
     * Invoked when a handshake, frame, or socket error occurs on a client connection.
     *
     * @param connection affected client connection, or {@code null} before upgrade completes
     * @param error failure cause
     */
    void onConnectionError(Connection connection, Throwable error);

    /**
     * Invoked when the server accept loop encounters an unexpected error.
     *
     * @param error server failure cause
     */
    void onServerError(Throwable error);
  }
}
