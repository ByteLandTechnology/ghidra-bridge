package app.byteland.ghidra.agent;

import java.io.IOException;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

final class AgentClientWebSocketListener implements WebSocket.Listener {
  static final int UNSUPPORTED_DATA_CLOSE_CODE = 1003;
  static final int MESSAGE_TOO_BIG_CLOSE_CODE = 1009;

  private static final int MAX_RETAINED_BUFFER_CHARS = 64 * 1024;
  private static final long CLOSE_TIMEOUT_SECONDS = 5L;

  private final AtomicReference<AgentClientChannels.MessageChannel> channelRef;
  private final CountDownLatch disconnectLatch;
  private final AgentMessageHandler messageHandler;
  private final StringBuilder pendingText = new StringBuilder();
  private long pendingUtf8Bytes;
  private boolean pendingHighSurrogate;
  private boolean closed;

  AgentClientWebSocketListener(
      AtomicReference<AgentClientChannels.MessageChannel> channelRef,
      CountDownLatch disconnectLatch,
      AgentMessageHandler messageHandler) {
    this.channelRef = channelRef;
    this.disconnectLatch = disconnectLatch;
    this.messageHandler = messageHandler;
  }

  @Override
  public void onOpen(WebSocket webSocket) {
  }

  @Override
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
    if (closed) {
      return null;
    }
    Utf8Advance advance = measureUtf8(data, pendingUtf8Bytes, pendingHighSurrogate);
    if (advance.bytes() > WebSocketFrames.MAX_FRAME_PAYLOAD_BYTES) {
      resetBuffer();
      AgentClient.logTransportError(
          "WebSocket client message exceeds limit",
          new IOException("WebSocket message payload exceeds limit: " + advance.bytes()));
      closeAndDisconnect(webSocket, MESSAGE_TOO_BIG_CLOSE_CODE, "message exceeds maximum size");
      return null;
    }
    if (!last) {
      pendingText.append(data);
      pendingUtf8Bytes = advance.bytes();
      pendingHighSurrogate = advance.highSurrogateCarry();
      webSocket.request(1);
      return null;
    }

    String message;
    if (pendingText.isEmpty()) {
      message = data.toString();
    } else {
      pendingText.append(data);
      message = pendingText.toString();
    }
    resetBuffer();
    try {
      messageHandler.handleMessage(channelRef.get(), message);
    } catch (RuntimeException failure) {
      // The reply did not transmit, so the connection is lost.
      // An aborted WebSocket calls neither onClose nor onError. Thus, end the session here.
      AgentClient.logTransportError("WebSocket client message failed", failure);
      disconnected();
      return null;
    }
    webSocket.request(1);
    return null;
  }

  @Override
  public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
    if (closed) {
      return null;
    }
    resetBuffer();
    closeAndDisconnect(webSocket, UNSUPPORTED_DATA_CLOSE_CODE, "binary frames not supported");
    return null;
  }

  @Override
  public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
    disconnected();
    return null;
  }

  @Override
  public void onError(WebSocket webSocket, Throwable error) {
    AgentClient.logTransportError("WebSocket client connection error", error);
    disconnected();
  }

  int pendingBufferCapacity() {
    return pendingText.capacity();
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void closeAndDisconnect(WebSocket webSocket, int statusCode, String reason) {
    try {
      CompletableFuture<WebSocket> closeFuture = webSocket.sendClose(statusCode, reason);
      if (closeFuture == null) {
        abortQuietly(webSocket);
      } else {
        closeFuture
            .orTimeout(CLOSE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .whenComplete((closedSocket, error) -> abortQuietly(webSocket));
      }
    } catch (RuntimeException closeFailure) {
      abortQuietly(webSocket);
    } finally {
      disconnected();
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void abortQuietly(WebSocket webSocket) {
    try {
      webSocket.abort();
    } catch (RuntimeException ignored) {
      // Ignore abort errors on an already closed or broken connection.
    }
  }

  private void resetBuffer() {
    boolean trim = pendingText.capacity() > MAX_RETAINED_BUFFER_CHARS;
    pendingText.setLength(0);
    if (trim) {
      pendingText.trimToSize();
    }
    pendingUtf8Bytes = 0;
    pendingHighSurrogate = false;
  }

  private void disconnected() {
    closed = true;
    resetBuffer();
    channelRef.set(null);
    disconnectLatch.countDown();
  }

  private static Utf8Advance measureUtf8(
      CharSequence data, long currentBytes, boolean highSurrogateCarry) {
    long bytes = currentBytes;
    boolean carry = highSurrogateCarry;
    int length = data.length();
    int index = 0;
    if (carry && length > 0) {
      carry = false;
      if (Character.isLowSurrogate(data.charAt(0))) {
        bytes += 1;
        index = 1;
        if (bytes > WebSocketFrames.MAX_FRAME_PAYLOAD_BYTES) {
          return new Utf8Advance(bytes, false);
        }
      }
    }
    while (index < length) {
      char ch = data.charAt(index);
      if (ch <= 0x7F) {
        bytes += 1;
      } else if (ch <= 0x7FF) {
        bytes += 2;
      } else if (Character.isHighSurrogate(ch)) {
        if (index + 1 < length) {
          if (Character.isLowSurrogate(data.charAt(index + 1))) {
            bytes += 4;
            index += 2;
            if (bytes > WebSocketFrames.MAX_FRAME_PAYLOAD_BYTES) {
              return new Utf8Advance(bytes, false);
            }
            continue;
          }
          bytes += 3;
        } else {
          bytes += 3;
          carry = true;
        }
      } else {
        bytes += 3;
      }
      if (bytes > WebSocketFrames.MAX_FRAME_PAYLOAD_BYTES) {
        return new Utf8Advance(bytes, false);
      }
      index++;
    }
    return new Utf8Advance(bytes, carry);
  }

  private record Utf8Advance(long bytes, boolean highSurrogateCarry) {}
}
