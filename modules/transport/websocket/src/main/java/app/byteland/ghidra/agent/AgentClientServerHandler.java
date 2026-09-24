package app.byteland.ghidra.agent;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

final class AgentClientServerHandler implements AgentWebSocketServer.Handler {
  private final AtomicReference<AgentClientChannels.MessageChannel> channelRef;
  private final CountDownLatch disconnectLatch;
  private final AgentMessageHandler messageHandler;

  AgentClientServerHandler(
      AtomicReference<AgentClientChannels.MessageChannel> channelRef,
      CountDownLatch disconnectLatch,
      AgentMessageHandler messageHandler) {
    this.channelRef = channelRef;
    this.disconnectLatch = disconnectLatch;
    this.messageHandler = messageHandler;
  }

  @Override
  public void onOpen(AgentWebSocketServer.Connection connection) {
    AgentClientChannels.MessageChannel channel = AgentClientChannels.server(connection);
    channelRef.set(channel);
    messageHandler.sendReady(channel);
  }

  @Override
  public void onText(AgentWebSocketServer.Connection connection, String message) {
    messageHandler.handleMessage(AgentClientChannels.server(connection), message);
  }

  @Override
  public void onClose(AgentWebSocketServer.Connection connection, int statusCode, String reason) {
    channelRef.set(null);
  }

  @Override
  public void onConnectionError(AgentWebSocketServer.Connection connection, Throwable error) {
    AgentClient.logTransportError("WebSocket server connection error", error);
  }

  @Override
  public void onServerError(Throwable error) {
    AgentClient.logTransportError("WebSocket server error", error);
    disconnectLatch.countDown();
  }
}
