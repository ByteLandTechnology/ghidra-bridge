package app.byteland.ghidra.agent;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

final class AgentServerConnection implements AgentWebSocketServer.Connection {
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
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  public void close(int statusCode, String reason) {
    if (!state.compareAndSet(State.OPEN, State.CLOSING)) {
      abortCloseInProgress();
      return;
    }
    byte[] reasonBytes = reason == null ? new byte[0] : reason.getBytes(StandardCharsets.UTF_8);
    ByteBuffer payload = ByteBuffer.allocate(Short.BYTES + reasonBytes.length);
    payload.putShort((short) statusCode);
    payload.put(reasonBytes);
    Throwable failure = null;
    if (writeLock.tryLock()) {
      try {
        if (!socketCloseStarted.get()) {
          WebSocketFrames.writeFrame(output, WebSocketFrames.CLOSE_OPCODE, payload.array());
        }
      } catch (IOException | RuntimeException writeFailure) {
        failure = writeFailure;
      } finally {
        writeLock.unlock();
      }
    }
    failure = closeSocketOnce(failure);
    throwCloseFailure(failure);
  }

  private void abortCloseInProgress() {
    if (state.get() == State.CLOSING) {
      throwCloseFailure(closeSocketOnce(null));
    }
  }

  @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CompareObjectsWithEquals"})
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
