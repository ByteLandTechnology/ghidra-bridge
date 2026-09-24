package app.byteland.ghidra.agent;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Embedded WebSocket server handling inbound JSON-RPC 2.0 connections.
 */
public final class AgentWebSocketServer implements AutoCloseable {
  public static final String DEFAULT_PATH = "/ws/agent";
  private static final int SERVER_SHUTDOWN_CLOSE_CODE = 1001;
  static final Object RESERVED_CONNECTION_SLOT = new Object();

  private final AgentConfig config;
  private final Handler handler;
  private final AtomicBoolean running = new AtomicBoolean(false);
  private final AtomicReference<Object> activeConnection = new AtomicReference<>();
  private final AtomicReference<Socket> pendingSocket = new AtomicReference<>();
  private ServerSocket serverSocket;

  public AgentWebSocketServer(AgentConfig config, Handler handler) {
    this.config = config;
    this.handler = handler;
  }

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
