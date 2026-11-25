package app.byteland.ghidra.agent;

import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
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
  private final AtomicReference<AgentServerConnection> activeConnection;
  private final AgentWebSocketServer.PendingSockets pendingSockets;
  private final long handshakeTimeoutNanos;

  AgentWebSocketConnectionRunner(
      AgentConfig config,
      AgentWebSocketServer.Handler handler,
      AtomicBoolean running,
      AtomicReference<AgentServerConnection> activeConnection,
      AgentWebSocketServer.PendingSockets pendingSockets,
      Duration handshakeTimeout) {
    this.config = config;
    this.handler = handler;
    this.running = running;
    this.activeConnection = activeConnection;
    this.pendingSockets = pendingSockets;
    this.handshakeTimeoutNanos = handshakeTimeout.toNanos();
  }

  void runConnection(Socket socket) {
    if (!pendingSockets.claimForRead(socket)) {
      return;
    }
    AgentServerConnection connection = null;
    boolean opened = false;
    CloseState closeState = new CloseState(NORMAL_CLOSE_CODE, NORMAL_CLOSE_REASON);
    try {
      try (socket) {
        socket.setTcpNoDelay(true);
        long deadlineNanos = System.nanoTime() + handshakeTimeoutNanos;
        WebSocketHandshake.HandshakeRequest request;
        try {
          request = WebSocketHandshake.readHandshake(socket, deadlineNanos);
          WebSocketHandshakeValidator.validate(config, request);
        } catch (WebSocketHandshake.HttpHandshakeException e) {
          closeState.reason = e.getMessage();
          pendingSockets.remove(socket);
          if (running.get()) {
            writeHandshakeFailure(socket, e);
          }
          return;
        }
        if (!running.get()) {
          return;
        }
        socket.setSoTimeout(0);
        AgentServerConnection candidate = new AgentServerConnection(socket);
        if (!activeConnection.compareAndSet(null, candidate)) {
          candidate.markClosed();
          pendingSockets.remove(socket);
          if (running.get()) {
            WebSocketHandshake.writeHttpResponse(
                socket.getOutputStream(),
                409,
                "Conflict",
                List.of("Connection: close"),
                "Bridge already has an active client");
            WebSocketHandshake.closeAfterHttpError(socket, 250, 16 * 1024);
          }
          return;
        }
        pendingSockets.remove(socket);
        if (!running.get()) {
          activeConnection.compareAndSet(candidate, null);
          candidate.markClosed();
          return;
        }
        connection = candidate;
        WebSocketHandshake.writeHandshakeResponse(socket.getOutputStream(), request.acceptKey());
        opened = true;
        handler.onOpen(connection);
        runFrameLoop(connection, closeState);
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
      pendingSockets.remove(socket);
      if (connection != null) {
        activeConnection.compareAndSet(connection, null);
        connection.markClosed();
      }
      if (opened) {
        handler.onClose(connection, closeState.code, closeState.reason);
      }
    }
  }

  private void writeHandshakeFailure(Socket socket, WebSocketHandshake.HttpHandshakeException e) {
    try {
      WebSocketHandshake.writeHttpResponse(
          socket.getOutputStream(),
          e.status(),
          e.reason(),
          List.of("Connection: close"),
          e.getMessage());
      WebSocketHandshake.closeAfterHttpError(socket, 1_000, 128 * 1024);
    } catch (IOException responseFailure) {
      e.addSuppressed(responseFailure);
      if (running.get()) {
        handler.onConnectionError(null, e);
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
