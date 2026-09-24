package app.byteland.ghidra.agent;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

final class AgentWebSocketAcceptor implements Runnable {
  private static final ThreadFactory CONNECTION_THREADS =
      Thread.ofPlatform().daemon().name("agent-ws-connection").factory();

  private final ServerSocket serverSocket;
  private final AgentWebSocketServer.Handler handler;
  private final AtomicBoolean running;
  private final AtomicReference<Object> activeConnection;
  private final AtomicReference<Socket> pendingSocket;
  private final AgentWebSocketConnectionRunner connectionRunner;
  private final ThreadFactory connectionThreadFactory;

  AgentWebSocketAcceptor(
      ServerSocket serverSocket,
      AgentWebSocketServer.Handler handler,
      AtomicBoolean running,
      AtomicReference<Object> activeConnection,
      AtomicReference<Socket> pendingSocket,
      AgentWebSocketConnectionRunner connectionRunner) {
    this(
        serverSocket,
        handler,
        running,
        activeConnection,
        pendingSocket,
        connectionRunner,
        CONNECTION_THREADS);
  }

  AgentWebSocketAcceptor(
      ServerSocket serverSocket,
      AgentWebSocketServer.Handler handler,
      AtomicBoolean running,
      AtomicReference<Object> activeConnection,
      AtomicReference<Socket> pendingSocket,
      AgentWebSocketConnectionRunner connectionRunner,
      ThreadFactory connectionThreadFactory) {
    this.serverSocket = serverSocket;
    this.handler = handler;
    this.running = running;
    this.activeConnection = activeConnection;
    this.pendingSocket = pendingSocket;
    this.connectionRunner = connectionRunner;
    this.connectionThreadFactory = connectionThreadFactory;
  }

  @Override
  @SuppressWarnings("PMD.CloseResource")
  public void run() {
    while (running.get()) {
      try {
        Socket socket = serverSocket.accept();
        if (!activeConnection.compareAndSet(null, AgentWebSocketServer.RESERVED_CONNECTION_SLOT)) {
          rejectBusy(socket);
          continue;
        }
        startConnectionThread(socket);
      } catch (IOException e) {
        if (running.get()) {
          handler.onServerError(e);
        }
        return;
      }
    }
  }

  private void rejectBusy(Socket socket) {
    try (socket) {
      WebSocketHandshake.writeHttpResponse(
          socket.getOutputStream(),
          409,
          "Conflict",
          List.of(),
          "Bridge already has an active client");
    } catch (IOException failure) {
      handler.onConnectionError(null, failure);
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void startConnectionThread(Socket socket) {
    pendingSocket.set(socket);
    try {
      Thread connectionThread =
          connectionThreadFactory.newThread(() -> connectionRunner.runConnection(socket));
      connectionThread.start();
    } catch (RuntimeException e) {
      pendingSocket.compareAndSet(socket, null);
      activeConnection.compareAndSet(AgentWebSocketServer.RESERVED_CONNECTION_SLOT, null);
      closeAfterFailedStart(socket, e);
      throw e;
    }
  }

  @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CompareObjectsWithEquals"})
  private static void closeAfterFailedStart(Socket socket, RuntimeException startFailure) {
    try {
      socket.close();
    } catch (IOException | RuntimeException closeFailure) {
      if (closeFailure != startFailure) {
        startFailure.addSuppressed(closeFailure);
      }
    }
  }
}
