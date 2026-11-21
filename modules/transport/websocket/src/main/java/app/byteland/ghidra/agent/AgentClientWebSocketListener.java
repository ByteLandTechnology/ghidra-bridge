package app.byteland.ghidra.agent;

import java.net.http.WebSocket;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

final class AgentClientWebSocketListener implements WebSocket.Listener {
  static final int MAX_RETAINED_BUFFER_CAPACITY = 64 * 1024;
  private static final int INITIAL_BUFFER_CAPACITY = 16;

  private final AtomicReference<AgentClientChannels.MessageChannel> channelRef;
  private final CountDownLatch disconnectLatch;
  private final AgentMessageHandler messageHandler;
  private StringBuilder pendingText = new StringBuilder(INITIAL_BUFFER_CAPACITY);

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
    if (last) {
      String message = consumeCompleteMessage(data);
      try {
        messageHandler.handleMessage(channelRef.get(), message);
      } catch (RuntimeException failure) {
        // The reply did not transmit, so the connection is lost.
        // An aborted WebSocket calls neither onClose nor onError. Thus, end the session here.
        AgentClient.logTransportError("WebSocket client message failed", failure);
        disconnected();
        return null;
      }
    } else {
      pendingText.append(data);
    }
    webSocket.request(1);
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

  int pendingBufferLength() {
    return pendingText.length();
  }

  int pendingBufferCapacity() {
    return pendingText.capacity();
  }

  private String consumeCompleteMessage(CharSequence data) {
    StringBuilder buffer = pendingText;
    if (buffer.isEmpty()) {
      return data.toString();
    }
    buffer.append(data);
    String message = buffer.toString();
    if (buffer.capacity() > MAX_RETAINED_BUFFER_CAPACITY) {
      pendingText = new StringBuilder(INITIAL_BUFFER_CAPACITY);
    } else {
      buffer.setLength(0);
    }
    return message;
  }

  private void disconnected() {
    pendingText = new StringBuilder(INITIAL_BUFFER_CAPACITY);
    channelRef.set(null);
    disconnectLatch.countDown();
  }
}
