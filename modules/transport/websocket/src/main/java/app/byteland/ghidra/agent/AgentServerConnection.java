package app.byteland.ghidra.agent;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;

final class AgentServerConnection implements AgentWebSocketServer.Connection {
  private static final byte[] EMPTY_PAYLOAD = new byte[0];
  private static final int CLOSE_DRAIN_TIMEOUT_MILLIS = 75;
  private static final int MAX_CLOSE_DRAIN_BYTES = 128 * 1024;
  private static final int CLOSE_DRAIN_BUFFER_BYTES = 4096;

  private final Socket socket;
  private final InputStream inputStream;
  private final OutputStream output;
  private final ReentrantLock writeLock = new ReentrantLock();
  private final AtomicReference<State> state = new AtomicReference<>(State.OPEN);
  private final AtomicBoolean socketCloseStarted = new AtomicBoolean();

  AgentServerConnection(Socket socket) throws IOException {
    this.socket = socket;
    this.inputStream = new BufferedInputStream(socket.getInputStream());
    this.output = socket.getOutputStream();
  }

  InputStream input() {
    return inputStream;
  }

  boolean isOpen() {
    return state.get() == State.OPEN && !socket.isClosed();
  }

  @Override
  public void sendText(String message) {
    try {
      writeFrameIfOpen(WebSocketFrames.TEXT_OPCODE, message.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new RuntimeException("Failed to send text frame", e);
    }
  }

  @Override
  public void close(int statusCode, String reason) {
    closeInternal(statusCode, reason, null);
  }

  void closeFromRunner(int statusCode, String reason, BooleanSupplier continueDrain) {
    closeInternal(statusCode, reason, Objects.requireNonNull(continueDrain, "continueDrain"));
  }

  private void closeInternal(int statusCode, String reason, BooleanSupplier continueDrain) {
    if (!state.compareAndSet(State.OPEN, State.CLOSING)) {
      abortCloseInProgress();
      return;
    }
    byte[] reasonBytes = reason == null ? new byte[0] : reason.getBytes(StandardCharsets.UTF_8);
    ByteBuffer payload = ByteBuffer.allocate(Short.BYTES + reasonBytes.length);
    payload.putShort((short) statusCode);
    payload.put(reasonBytes);
    Throwable failure = null;
    boolean wroteCloseFrame = false;
    if (writeLock.tryLock()) {
      try {
        if (!socketCloseStarted.get()) {
          WebSocketFrames.writeFrame(output, WebSocketFrames.CLOSE_OPCODE, payload.array());
          wroteCloseFrame = true;
        }
      } catch (IOException | RuntimeException writeFailure) {
        failure = writeFailure;
      } finally {
        writeLock.unlock();
      }
    }
    if (wroteCloseFrame
        && failure == null
        && continueDrain != null
        && continueDrain.getAsBoolean()
        && !socketCloseStarted.get()) {
      drainBeforeSocketClose(continueDrain);
    }
    failure = closeSocketOnce(failure);
    throwCloseFailure(failure);
  }

  private void drainBeforeSocketClose(BooleanSupplier continueDrain) {
    try {
      if (!socket.isClosed() && !socket.isOutputShutdown()) {
        socket.shutdownOutput();
      }
      if (!socket.isClosed() && !socket.isInputShutdown()) {
        InputStream rawInput = socket.getInputStream();
        byte[] buffer = new byte[CLOSE_DRAIN_BUFFER_BYTES];
        int totalRead = 0;
        long deadlineNanos =
            System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CLOSE_DRAIN_TIMEOUT_MILLIS);
        while (totalRead < MAX_CLOSE_DRAIN_BYTES
            && continueDrain.getAsBoolean()
            && !socketCloseStarted.get()
            && !socket.isClosed()) {
          long remainingMillis =
              TimeUnit.NANOSECONDS.toMillis(deadlineNanos - System.nanoTime());
          if (remainingMillis <= 0L) {
            break;
          }
          socket.setSoTimeout((int) Math.max(1L, remainingMillis));
          int step = Math.min(buffer.length, MAX_CLOSE_DRAIN_BYTES - totalRead);
          int read = rawInput.read(buffer, 0, step);
          if (read < 0) {
            break;
          }
          totalRead += read;
        }
      }
    } catch (IOException ignored) {
      // Ignore read or close errors after the server sends the close frame.
    }
  }

  private void abortCloseInProgress() {
    if (state.get() == State.CLOSING) {
      throwCloseFailure(closeSocketOnce(null));
    }
  }

  private Throwable closeSocketOnce(Throwable priorFailure) {
    if (!socketCloseStarted.compareAndSet(false, true)) {
      return priorFailure;
    }
    Throwable result = priorFailure;
    try {
      socket.close();
    } catch (IOException | RuntimeException closeFailure) {
      if (result == null) {
        result = closeFailure;
      } else if (result != closeFailure) {
        result.addSuppressed(closeFailure);
      }
    } finally {
      state.set(State.CLOSED);
    }
    return result;
  }

  private static void throwCloseFailure(Throwable failure) {
    if (failure instanceof RuntimeException runtimeFailure) {
      throw runtimeFailure;
    }
    if (failure instanceof IOException ioFailure) {
      throw new UncheckedIOException("Failed to close WebSocket connection", ioFailure);
    }
  }

  void sendPing() throws IOException {
    sendControlFrame(WebSocketFrames.PING_OPCODE, EMPTY_PAYLOAD);
  }

  void sendControlFrame(int opcode, byte[] payload) throws IOException {
    writeFrameIfOpen(opcode, payload);
  }

  private void writeFrameIfOpen(int opcode, byte[] payload) throws IOException {
    if (!isOpen()) {
      return;
    }
    writeLock.lock();
    try {
      if (isOpen()) {
        WebSocketFrames.writeFrame(output, opcode, payload);
      }
    } finally {
      writeLock.unlock();
    }
  }

  void markClosed() {
    state.set(State.CLOSED);
  }

  private enum State {
    OPEN,
    CLOSING,
    CLOSED
  }
}
