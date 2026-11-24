package app.byteland.ghidra.agent;

import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

final class AgentWebSocketConnectionRunner {
  static final Duration DEFAULT_KEEPALIVE_INTERVAL = Duration.ofSeconds(5);
  static final Duration DEFAULT_PONG_TIMEOUT = Duration.ofSeconds(10);
  private static final String NORMAL_CLOSE_REASON = "closed";
  private static final String KEEPALIVE_TIMEOUT_REASON = "keepalive timeout";

  private final AgentConfig config;
  private final AgentWebSocketServer.Handler handler;
  private final AtomicBoolean running;
  private final AtomicReference<AgentServerConnection> activeConnection;
  private final AgentWebSocketServer.PendingSockets pendingSockets;
  private final long handshakeTimeoutNanos;
  private final int keepaliveIntervalMillis;
  private final long pongTimeoutNanos;

  AgentWebSocketConnectionRunner(
      AgentConfig config,
      AgentWebSocketServer.Handler handler,
      AtomicBoolean running,
      AtomicReference<AgentServerConnection> activeConnection,
      AgentWebSocketServer.PendingSockets pendingSockets,
      Duration handshakeTimeout) {
    this(
        config,
        handler,
        running,
        activeConnection,
        pendingSockets,
        handshakeTimeout,
        DEFAULT_KEEPALIVE_INTERVAL,
        DEFAULT_PONG_TIMEOUT);
  }

  AgentWebSocketConnectionRunner(
      AgentConfig config,
      AgentWebSocketServer.Handler handler,
      AtomicBoolean running,
      AtomicReference<AgentServerConnection> activeConnection,
      AgentWebSocketServer.PendingSockets pendingSockets,
      Duration handshakeTimeout,
      Duration keepaliveInterval,
      Duration pongTimeout) {
    this.config = config;
    this.handler = handler;
    this.running = running;
    this.activeConnection = activeConnection;
    this.pendingSockets = pendingSockets;
    this.handshakeTimeoutNanos = handshakeTimeout.toNanos();
    this.keepaliveIntervalMillis = toTimeoutMillis(keepaliveInterval, "keepaliveInterval");
    this.pongTimeoutNanos = requirePositiveDuration(pongTimeout, "pongTimeout").toNanos();
  }

  void runConnection(Socket socket) {
    AgentServerConnection connection = null;
    boolean opened = false;
    CloseState closeState =
        new CloseState(WebSocketFrames.NORMAL_CLOSE_STATUS, NORMAL_CLOSE_REASON);
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
          writeHandshakeFailure(socket, e);
          return;
        }
        if (!running.get()) {
          return;
        }
        socket.setSoTimeout(keepaliveIntervalMillis);
        AgentServerConnection candidate = new AgentServerConnection(socket);
        if (!activeConnection.compareAndSet(null, candidate)) {
          candidate.markClosed();
          if (running.get()) {
            WebSocketHandshake.writeHttpResponse(
                socket.getOutputStream(),
                409,
                "Conflict",
                List.of(),
                "Bridge already has an active client");
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
        runFrameLoop(socket, connection, closeState);
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
          socket.getOutputStream(), e.status(), e.reason(), List.of(), e.getMessage());
    } catch (IOException responseFailure) {
      e.addSuppressed(responseFailure);
      if (running.get()) {
        handler.onConnectionError(null, e);
      }
    }
  }

  private void runFrameLoop(
      Socket socket, AgentServerConnection connection, CloseState closeState) throws IOException {
    FragmentAssembler fragments = new FragmentAssembler();
    boolean awaitingPong = false;
    long pongDeadlineNanos = 0L;
    while (running.get() && connection.isOpen()) {
      if (awaitingPong) {
        long remainingNanos = pongDeadlineNanos - System.nanoTime();
        if (remainingNanos <= 0L) {
          closeWith(
              connection,
              closeState,
              WebSocketFrames.GOING_AWAY_CLOSE_STATUS,
              KEEPALIVE_TIMEOUT_REASON);
          return;
        }
        int waitMillis =
            (int)
                Math.min(
                    keepaliveIntervalMillis,
                    Math.max(1L, (remainingNanos + 999_999L) / 1_000_000L));
        socket.setSoTimeout(waitMillis);
      } else {
        socket.setSoTimeout(keepaliveIntervalMillis);
      }

      WebSocketFrames.Frame frame;
      try {
        frame = WebSocketFrames.readFrame(connection.input());
      } catch (SocketTimeoutException idleTimeout) {
        if (!running.get() || !connection.isOpen()) {
          return;
        }
        if (!awaitingPong) {
          connection.sendPing();
          awaitingPong = true;
          pongDeadlineNanos = System.nanoTime() + pongTimeoutNanos;
          continue;
        }
        if (System.nanoTime() - pongDeadlineNanos >= 0L) {
          closeWith(
              connection,
              closeState,
              WebSocketFrames.GOING_AWAY_CLOSE_STATUS,
              KEEPALIVE_TIMEOUT_REASON);
          return;
        }
        continue;
      } catch (WebSocketFrames.WebSocketProtocolException protocolError) {
        closeWith(connection, closeState, protocolError.closeCode(), protocolError.getMessage());
        return;
      }

      if (frame.opcode() == WebSocketFrames.PONG_OPCODE) {
        awaitingPong = false;
        continue;
      }
      if (frame.opcode() != WebSocketFrames.CLOSE_OPCODE
          && awaitingPong
          && System.nanoTime() - pongDeadlineNanos >= 0L) {
        closeWith(
            connection,
            closeState,
            WebSocketFrames.GOING_AWAY_CLOSE_STATUS,
            KEEPALIVE_TIMEOUT_REASON);
        return;
      }
      try {
        if (!handleFrame(connection, frame, fragments, closeState)) {
          return;
        }
      } catch (WebSocketFrames.WebSocketProtocolException protocolError) {
        closeWith(connection, closeState, protocolError.closeCode(), protocolError.getMessage());
        return;
      }
    }
  }

  private boolean handleFrame(
      AgentServerConnection connection,
      WebSocketFrames.Frame frame,
      FragmentAssembler fragments,
      CloseState closeState)
      throws IOException {
    switch (frame.opcode()) {
      case WebSocketFrames.TEXT_OPCODE -> {
        if (fragments.inProgress()) {
          throw new WebSocketFrames.WebSocketProtocolException(
              WebSocketFrames.PROTOCOL_ERROR_CLOSE_STATUS,
              "Unexpected text frame before final fragment");
        }
        if (frame.fin()) {
          String text = WebSocketFrames.decodeUtf8(frame.payloadView());
          handler.onText(connection, text);
          return true;
        }
        fragments.start(frame.payloadView());
        return true;
      }
      case WebSocketFrames.CONTINUATION_OPCODE -> {
        if (!fragments.inProgress()) {
          throw new WebSocketFrames.WebSocketProtocolException(
              WebSocketFrames.PROTOCOL_ERROR_CLOSE_STATUS, "Unexpected continuation frame");
        }
        fragments.append(frame.payloadView());
        if (frame.fin()) {
          String text = fragments.finishUtf8();
          handler.onText(connection, text);
        }
        return true;
      }
      case WebSocketFrames.BINARY_OPCODE -> {
        if (fragments.inProgress()) {
          throw new WebSocketFrames.WebSocketProtocolException(
              WebSocketFrames.PROTOCOL_ERROR_CLOSE_STATUS,
              "Unexpected binary frame before final fragment");
        }
        closeWith(
            connection,
            closeState,
            WebSocketFrames.UNSUPPORTED_DATA_CLOSE_STATUS,
            "binary frames not supported");
        return false;
      }
      case WebSocketFrames.CLOSE_OPCODE -> {
        WebSocketFrames.CloseInfo closeInfo =
            WebSocketFrames.parseClosePayload(frame.payloadView());
        closeWith(connection, closeState, closeInfo.code(), closeInfo.reason());
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
        closeWith(
            connection,
            closeState,
            WebSocketFrames.PROTOCOL_ERROR_CLOSE_STATUS,
            "unsupported frame");
        return false;
      }
    }
  }

  private static void closeWith(
      AgentServerConnection connection, CloseState closeState, int code, String reason) {
    closeState.code = code;
    closeState.reason = reason;
    connection.close(code, reason);
  }

  private static Duration requirePositiveDuration(Duration duration, String name) {
    Objects.requireNonNull(duration, name);
    if (duration.isZero() || duration.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
    return duration;
  }

  private static int toTimeoutMillis(Duration duration, String name) {
    long millis = requirePositiveDuration(duration, name).toMillis();
    if (millis <= 0L) {
      return 1;
    }
    return (int) Math.min(Integer.MAX_VALUE, millis);
  }

  private static final class FragmentAssembler {
    private static final int INITIAL_CAPACITY = 256;
    private byte[] buffer;
    private int length;
    private boolean active;

    boolean inProgress() {
      return active;
    }

    void start(byte[] payload) throws WebSocketFrames.WebSocketProtocolException {
      if (payload.length > WebSocketFrames.MAX_MESSAGE_BYTES) {
        throw new WebSocketFrames.WebSocketProtocolException(
            WebSocketFrames.MESSAGE_TOO_BIG_CLOSE_STATUS, "Message exceeds 16 MiB limit");
      }
      int capacity =
          Math.min(WebSocketFrames.MAX_MESSAGE_BYTES, Math.max(INITIAL_CAPACITY, payload.length));
      buffer = new byte[capacity];
      System.arraycopy(payload, 0, buffer, 0, payload.length);
      length = payload.length;
      active = true;
    }

    void append(byte[] payload) throws WebSocketFrames.WebSocketProtocolException {
      long required = (long) length + payload.length;
      if (required > WebSocketFrames.MAX_MESSAGE_BYTES) {
        reset();
        throw new WebSocketFrames.WebSocketProtocolException(
            WebSocketFrames.MESSAGE_TOO_BIG_CLOSE_STATUS, "Message exceeds 16 MiB limit");
      }
      if (required > buffer.length) {
        int newCapacity =
            (int)
                Math.min(
                    WebSocketFrames.MAX_MESSAGE_BYTES,
                    Math.max((long) buffer.length << 1, required));
        buffer = Arrays.copyOf(buffer, newCapacity);
      }
      System.arraycopy(payload, 0, buffer, length, payload.length);
      length = (int) required;
    }

    String finishUtf8() throws WebSocketFrames.WebSocketProtocolException {
      byte[] assembled = buffer;
      int assembledLength = length;
      reset();
      return WebSocketFrames.decodeUtf8(assembled, 0, assembledLength);
    }

    private void reset() {
      buffer = null;
      length = 0;
      active = false;
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
