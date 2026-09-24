package app.byteland.ghidra.agent;

import java.net.http.WebSocket;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

final class AgentClientWebSocketListener implements WebSocket.Listener {
  private final AtomicReference<AgentClientChannels.MessageChannel> channelRef;
  private final CountDownLatch disconnectLatch;
  private final AgentMessageHandler messageHandler;
  private String pendingText = "";

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
  public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
    if (last) {
      String message = pendingText + data;
      pendingText = "";
      messageHandler.handleMessage(channelRef.get(), message);
    } else {
      pendingText += data;
    }
    webSocket.request(1);
    return null;
  }

  @Override
  public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
    channelRef.set(null);
    disconnectLatch.countDown();
    return null;
  }

  @Override
  public void onError(WebSocket webSocket, Throwable error) {
    AgentClient.logTransportError("WebSocket client connection error", error);
    channelRef.set(null);
    disconnectLatch.countDown();
  }
}
