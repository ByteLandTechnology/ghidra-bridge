package app.byteland.ghidra.agent;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.BridgeError;
import java.util.Map;

final class AgentMessageHandler {
  private final AgentConfig config;
  private final AgentDispatcher dispatcher;
  private final Runnable disconnectAction;

  AgentMessageHandler(AgentConfig config, AgentDispatcher dispatcher, Runnable disconnectAction) {
    this.config = config;
    this.dispatcher = dispatcher;
    this.disconnectAction = disconnectAction;
  }

  @SuppressWarnings("unchecked")
  void handleMessage(AgentClientChannels.MessageChannel channel, String message) {
    if (channel == null) return;
    Object parsed;
    try {
      parsed = JsonUtil.parse(message);
    } catch (IllegalArgumentException invalidJson) {
      sendProtocolError(channel, -32700, "parse_error", "Invalid JSON");
      return;
    }
    if (!(parsed instanceof Map<?, ?> raw)) {
      sendProtocolError(channel, -32600, "invalid_request", "Message must be an object");
      return;
    }
    MessageEnvelope envelope;
    try {
      envelope = MessageEnvelope.fromMap((Map<String, Object>) raw);
    } catch (ApiException invalidEnvelope) {
      sendProtocolError(
          channel, -32600, invalidEnvelope.error().code(), invalidEnvelope.error().message());
      return;
    }
    if (envelope instanceof MessageEnvelope.Request request) {
      handleRequest(channel, request);
    } else if (envelope instanceof MessageEnvelope.Notification notification) {
      handleNotification(notification);
    }
  }

  void sendReady(AgentClientChannels.MessageChannel channel) {
    MessageEnvelope.Notification ready =
        new MessageEnvelope.Notification(
            "ghidra.ready",
            Map.of(
                "session_id", config.sessionId(),
                "program_name", dispatcher.getProgramName()));
    channel.sendText(JsonUtil.toJson(ready.toMap()));
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void handleRequest(
      AgentClientChannels.MessageChannel channel, MessageEnvelope.Request request) {
    MessageEnvelope.Response response;
    try {
      Object result = dispatcher.dispatch(request.method(), request.params());
      response = new MessageEnvelope.Response(request.id(), result, null);
    } catch (Exception error) {
      response = AgentErrorMapper.errorResponse(request.id(), error);
    }
    channel.sendText(JsonUtil.toJson(response.toMap()));
    if (dispatcher.isShuttingDown()) {
      disconnectAction.run();
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void handleNotification(MessageEnvelope.Notification notification) {
    try {
      dispatcher.dispatch(notification.method(), notification.params());
    } catch (Exception ignored) {
      return;
    }
    if (dispatcher.isShuttingDown()) {
      disconnectAction.run();
    }
  }

  private static void sendProtocolError(
      AgentClientChannels.MessageChannel channel, int rpcCode, String code, String message) {
    BridgeError error = new BridgeError(400, code, message, null, Map.of());
    MessageEnvelope.Response response =
        new MessageEnvelope.Response(
            null, null, new MessageEnvelope.RpcError(rpcCode, message, error.toMap()));
    channel.sendText(JsonUtil.toJson(response.toMap()));
  }
}
