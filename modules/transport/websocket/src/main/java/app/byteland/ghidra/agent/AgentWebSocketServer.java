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
  /** Default HTTP path for inbound WebSocket requests. */
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
   * Creates an embedded WebSocket server for the given configuration and handler.
   *
   * @param config WebSocket server configuration
   * @param handler connection and message event handler
   */
  public AgentWebSocketServer(AgentConfig config, Handler handler) {
    this.config = config;
    this.handler = handler;
  }

  /**
   * Binds the listener socket and starts the background accept thread.
   *
   * @throws IOException if the server socket fails to bind
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

  /**
   * Represents an active inbound WebSocket client connection.
   */
  public interface Connection {
    /**
     * Sends one UTF-8 text frame to the client.
     *
     * @param message UTF-8 JSON-RPC message text
     */
    void sendText(String message);

    /**
     * Sends a WebSocket close frame and closes the client socket.
     *
     * @param statusCode WebSocket close status code
     * @param reason close reason string
     */
    void close(int statusCode, String reason);
  }

  /**
   * Receives connection, frame, and error callbacks from the WebSocket server.
   */
  public interface Handler {
    /**
     * Invoked after a client completes the WebSocket upgrade handshake.
     *
     * @param connection accepted client connection
     */
    void onOpen(Connection connection);

    /**
     * Invoked when a complete UTF-8 text frame arrives from the client.
     *
     * @param connection source client connection
     * @param message decoded text frame payload
     */
    void onText(Connection connection, String message);

    /**
     * Invoked after a client connection closes.
     *
     * @param connection closed client connection
     * @param statusCode WebSocket close status code
     * @param reason close reason text
     */
    void onClose(Connection connection, int statusCode, String reason);

    /**
     * Invoked when a connection handshake or frame loop fails.
     *
     * @param connection affected client connection, or null before handshake completion
     * @param error failure cause
     */
    void onConnectionError(Connection connection, Throwable error);

    /**
     * Invoked when the server listener socket fails.
     *
     * @param error server socket error
     */
    void onServerError(Throwable error);
  }
}
