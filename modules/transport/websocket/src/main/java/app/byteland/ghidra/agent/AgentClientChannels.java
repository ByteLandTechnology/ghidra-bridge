package app.byteland.ghidra.agent;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

final class AgentClientChannels {
  private static final Duration DEFAULT_OPERATION_TIMEOUT = Duration.ofSeconds(30);

  private AgentClientChannels() {}

  interface MessageChannel {
    void sendText(String message);

    void close();

    void close(int code, String reason);
  }

  static final class ChannelSendException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    ChannelSendException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  static OutboundMessageChannel outbound(WebSocket webSocket) {
    return outbound(webSocket, DEFAULT_OPERATION_TIMEOUT);
  }

  static OutboundMessageChannel outbound(WebSocket webSocket, Duration operationTimeout) {
    return new OutboundMessageChannel(webSocket, operationTimeout);
  }

  static MessageChannel server(AgentWebSocketServer.Connection connection) {
    return new ServerMessageChannel(connection);
  }

  static final class OutboundMessageChannel implements MessageChannel {
    private final WebSocket webSocket;
    private final Duration operationTimeout;

    private OutboundMessageChannel(WebSocket webSocket, Duration operationTimeout) {
      this.webSocket = Objects.requireNonNull(webSocket, "webSocket");
      this.operationTimeout = requirePositive(operationTimeout);
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public synchronized void sendText(String message) {
      try {
        await(webSocket.sendText(message, true), "sendText", operationTimeout);
      } catch (ChannelSendException sendFailure) {
        throw sendFailure;
      } catch (RuntimeException failure) {
        abortAfter(failure);
        throw new ChannelSendException("WebSocket sendText failed", failure);
      }
    }

    /**
     * Sends a ping and waits a maximum of {@code timeout} for the send. A send fails if the peer
     * closed the connection. This also occurs when the WebSocket did not report the close.
     */
    synchronized void ping(Duration timeout) {
      await(webSocket.sendPing(ByteBuffer.allocate(0)), "sendPing", timeout);
    }

    /** Closes the connection at once, without a close handshake. */
    void abort() {
      webSocket.abort();
    }

    @Override
    public synchronized void close() {
      close(WebSocket.NORMAL_CLOSURE, "agent shutdown");
    }

    @Override
    public synchronized void close(int code, String reason) {
      await(webSocket.sendClose(code, reason), "sendClose", operationTimeout);
    }

    @SuppressWarnings("PMD.PreserveStackTrace")
    private void await(
        CompletableFuture<WebSocket> operation, String operationName, Duration limit) {
      Objects.requireNonNull(operation, operationName + " future");
      try {
        operation.get(limit.toNanos(), TimeUnit.NANOSECONDS);
      } catch (InterruptedException interrupted) {
        operation.cancel(true);
        Thread.currentThread().interrupt();
        IllegalStateException failure =
            new IllegalStateException(
                "Interrupted while waiting for WebSocket " + operationName, interrupted);
        abortAfter(failure);
        throw failure;
      } catch (TimeoutException timeout) {
        operation.cancel(true);
        IllegalStateException failure =
            new IllegalStateException(
                "Timed out waiting for WebSocket "
                    + operationName
                    + " after "
                    + limit.toMillis()
                    + "ms",
                timeout);
        abortAfter(failure);
        throw failure;
      } catch (ExecutionException failed) {
        RuntimeException failure = mapFailure(operationName, failed.getCause());
        abortAfter(failure);
        throw failure;
      }
    }

    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CompareObjectsWithEquals"})
    private void abortAfter(RuntimeException failure) {
      try {
        webSocket.abort();
      } catch (RuntimeException abortFailure) {
        if (failure != abortFailure) {
          failure.addSuppressed(abortFailure);
        }
      }
    }

    private static RuntimeException mapFailure(String operationName, Throwable failure) {
      if (failure instanceof IOException ioFailure) {
        return new UncheckedIOException("WebSocket " + operationName + " failed", ioFailure);
      }
      if (failure instanceof RuntimeException runtimeFailure) {
        return runtimeFailure;
      }
      if (failure instanceof Error error) {
        throw error;
      }
      return new IllegalStateException("WebSocket " + operationName + " failed", failure);
    }

    private static Duration requirePositive(Duration timeout) {
      Objects.requireNonNull(timeout, "operationTimeout");
      if (timeout.isZero() || timeout.isNegative()) {
        throw new IllegalArgumentException("operationTimeout must be positive");
      }
      return timeout;
    }
  }

  private static final class ServerMessageChannel implements MessageChannel {
    private final AgentWebSocketServer.Connection connection;

    private ServerMessageChannel(AgentWebSocketServer.Connection connection) {
      this.connection = connection;
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public void sendText(String message) {
      try {
        connection.sendText(message);
      } catch (ChannelSendException sendFailure) {
        throw sendFailure;
      } catch (RuntimeException failure) {
        throw new ChannelSendException("WebSocket sendText failed", failure);
      }
    }

    @Override
    public void close() {
      connection.close(1000, "agent shutdown");
    }

    @Override
    public void close(int code, String reason) {
      connection.close(code, reason);
    }
  }
}
