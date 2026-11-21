package app.byteland.ghidra.agent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Embedded WebSocket server for inbound JSON-RPC 2.0 connections.
 */
public final class AgentWebSocketServer implements AutoCloseable {
  /** Default WebSocket request path for inbound agent connections. */
  public static final String DEFAULT_PATH = "/ws/agent";
  private static final int SERVER_SHUTDOWN_CLOSE_CODE = 1001;
  static final Object RESERVED_CONNECTION_SLOT = new Object();

  private final AgentConfig config;
  private final Handler handler;
  private final AtomicBoolean running = new AtomicBoolean(false);
  private final AtomicReference<Object> activeConnection = new AtomicReference<>();
  private final AtomicReference<Socket> pendingSocket = new AtomicReference<>();
  private ServerSocket serverSocket;

  /**
   * Creates an embedded WebSocket server for {@code config} and {@code handler}.
   *
   * @param config server bind and authentication configuration
   * @param handler callback handler for connection and message events
   */
  public AgentWebSocketServer(AgentConfig config, Handler handler) {
    this.config = config;
    this.handler = handler;
  }

  /**
   * Binds the server socket and starts the background accept loop.
   *
   * @throws IOException if binding the server socket fails
   */
  @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CloseResource"})
  public void start() throws IOException {
    if (!running.compareAndSet(false, true)) {
      return;
    }
    ServerSocket socket = new ServerSocket();
    try {
      socket.bind(new InetSocketAddress(config.host(), config.port()));
      AgentWebSocketConnectionRunner connectionRunner =
          new AgentWebSocketConnectionRunner(
              config, handler, running, activeConnection, pendingSocket);
      AgentWebSocketAcceptor acceptor =
          new AgentWebSocketAcceptor(
              socket, handler, running, activeConnection, pendingSocket, connectionRunner);
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

  /** Active WebSocket client connection accepted by the server. */
  public interface Connection {
    /**
     * Sends a UTF-8 text frame to the connected client.
     *
     * @param message text payload to send
     */
    void sendText(String message);

    /**
     * Sends a WebSocket close frame and closes the connection.
     *
     * @param statusCode WebSocket close status code
     * @param reason short close reason text
     */
    void close(int statusCode, String reason);
  }

  /** Receives connection lifecycle, frame, and server error callbacks. */
  public interface Handler {
    /**
     * Called after the WebSocket handshake completes.
     *
     * @param connection accepted client connection
     */
    void onOpen(Connection connection);

    /**
     * Called when a complete UTF-8 text message arrives.
     *
     * @param connection source client connection
     * @param message received text payload
     */
    void onText(Connection connection, String message);

    /**
     * Called when a client connection closes.
     *
     * @param connection closed client connection
     * @param statusCode WebSocket close status code
     * @param reason close reason text
     */
    void onClose(Connection connection, int statusCode, String reason);

    /**
     * Called when an error occurs on a client connection.
     *
     * @param connection affected client connection, or {@code null} before handshake
     * @param error connection failure
     */
    void onConnectionError(Connection connection, Throwable error);

    /**
     * Called when an accept or server socket error occurs.
     *
     * @param error server failure
     */
    void onServerError(Throwable error);
  }
}
