package app.byteland.ghidra.agent;

import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

final class AgentWebSocketConnectionRunner {
  private static final int NORMAL_CLOSE_CODE = 1000;
  private static final int UNSUPPORTED_DATA_CLOSE_CODE = 1003;
  private static final String NORMAL_CLOSE_REASON = "closed";

  private final AgentConfig config;
  private final AgentWebSocketServer.Handler handler;
  private final AtomicBoolean running;
  private final AtomicReference<Object> activeConnection;
  private final AtomicReference<Socket> pendingSocket;

  AgentWebSocketConnectionRunner(
      AgentConfig config,
      AgentWebSocketServer.Handler handler,
      AtomicBoolean running,
      AtomicReference<Object> activeConnection,
      AtomicReference<Socket> pendingSocket) {
    this.config = config;
    this.handler = handler;
    this.running = running;
    this.activeConnection = activeConnection;
    this.pendingSocket = pendingSocket;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  void runConnection(Socket socket) {
    AgentServerConnection connection = null;
    CloseState closeState = new CloseState(NORMAL_CLOSE_CODE, NORMAL_CLOSE_REASON);
    try (socket) {
      socket.setTcpNoDelay(true);
      WebSocketHandshake.HandshakeRequest request =
          WebSocketHandshake.readHandshake(socket.getInputStream());
      WebSocketHandshakeValidator.validate(config, request);
      connection = new AgentServerConnection(socket);
      if (!activeConnection.compareAndSet(
          AgentWebSocketServer.RESERVED_CONNECTION_SLOT, connection)) {
        connection.markClosed();
        closeState.reason = "server shutdown";
        return;
      }
      pendingSocket.compareAndSet(socket, null);
      WebSocketHandshake.writeHandshakeResponse(socket.getOutputStream(), request.acceptKey());
      handler.onOpen(connection);
      runFrameLoop(connection, closeState);
    } catch (WebSocketHandshake.HttpHandshakeException e) {
      closeState.reason = e.getMessage();
      try {
        WebSocketHandshake.writeHttpResponse(
            socket.getOutputStream(), e.status(), e.reason(), List.of(), e.getMessage());
      } catch (IOException responseFailure) {
        e.addSuppressed(responseFailure);
        handler.onConnectionError(connection, e);
      }
    } catch (EOFException ignored) {
      closeState.reason = "peer disconnected";
    } catch (IOException e) {
      closeState.reason = e.getMessage() == null ? "io error" : e.getMessage();
      if (running.get()) {
        handler.onConnectionError(connection, e);
      }
    } catch (RuntimeException e) {
      closeState.reason = e.getMessage() == null ? "runtime error" : e.getMessage();
      handler.onConnectionError(connection, e);
    } finally {
      pendingSocket.compareAndSet(socket, null);
      activeConnection.compareAndSet(
          connection != null ? connection : AgentWebSocketServer.RESERVED_CONNECTION_SLOT, null);
      if (connection != null) {
        connection.markClosed();
      }
      if (connection != null) {
        handler.onClose(connection, closeState.code, closeState.reason);
      }
    }
  }

  private void runFrameLoop(AgentServerConnection connection, CloseState closeState)
      throws IOException {
    while (running.get() && connection.isOpen()) {
      if (!handleFrame(connection, WebSocketFrames.readFrame(connection.input()), closeState)) {
        return;
      }
    }
  }

  private boolean handleFrame(
      AgentServerConnection connection, WebSocketFrames.Frame frame, CloseState closeState)
      throws IOException {
    switch (frame.opcode()) {
      case WebSocketFrames.TEXT_OPCODE -> {
        if (!frame.fin()) {
          connection.close(UNSUPPORTED_DATA_CLOSE_CODE, "fragmented text not supported");
          return false;
        }
        handler.onText(connection, new String(frame.payloadView(), StandardCharsets.UTF_8));
        return true;
      }
      case WebSocketFrames.CLOSE_OPCODE -> {
        closeState.code = WebSocketFrames.closeStatus(frame.payloadView());
        closeState.reason = WebSocketFrames.closeReason(frame.payloadView());
        connection.close(closeState.code, closeState.reason);
        return false;
      }
      case WebSocketFrames.PING_OPCODE -> {
        connection.sendControlFrame(WebSocketFrames.PONG_OPCODE, frame.payloadView());
        return true;
      }
      case WebSocketFrames.PONG_OPCODE -> {
        return true;
      }
      default -> {
        connection.close(UNSUPPORTED_DATA_CLOSE_CODE, "unsupported frame");
        return false;
      }
    }
  }

  private static final class CloseState {
    private int code;
    private String reason;

    private CloseState(int code, String reason) {
      this.code = code;
      this.reason = reason;
    }
  }
}
