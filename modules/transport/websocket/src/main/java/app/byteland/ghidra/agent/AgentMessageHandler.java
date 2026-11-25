package app.byteland.ghidra.agent;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.BridgeError;
import java.util.Map;

final class AgentMessageHandler {
  static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024;

  private final AgentConfig config;
  private final AgentDispatcher dispatcher;
  private final Runnable disconnectAction;

  AgentMessageHandler(AgentConfig config, AgentDispatcher dispatcher, Runnable disconnectAction) {
    this.config = config;
    this.dispatcher = dispatcher;
    this.disconnectAction = disconnectAction;
  }

  void handleMessage(AgentClientChannels.MessageChannel channel, String message) {
    if (channel == null) return;
    Object parsed;
    try {
      parsed = JsonUtil.parse(message);
    } catch (IllegalArgumentException invalidJson) {
      sendProtocolError(channel, -32700, "parse_error", "Invalid JSON");
      return;
    } catch (RuntimeException invalidMessage) {
      sendProtocolError(channel, -32600, "invalid_request", "Invalid JSON-RPC message");
      return;
    }
    handleParsed(channel, parsed);
  }

  @SuppressWarnings("unchecked")
  void handleParsed(AgentClientChannels.MessageChannel channel, Object parsed) {
    if (channel == null) return;
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
    } catch (RuntimeException invalidEnvelope) {
      sendProtocolError(channel, -32600, "invalid_request", "Invalid JSON-RPC message");
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

  private void handleRequest(
      AgentClientChannels.MessageChannel channel, MessageEnvelope.Request request) {
    String serialized;
    try {
      Object result = dispatcher.dispatch(request.method(), request.params());
      MessageEnvelope.Response response = new MessageEnvelope.Response(request.id(), result, null);
      serialized = JsonUtil.toJson(response.toMap(), MAX_MESSAGE_BYTES);
    } catch (Exception error) {
      serialized = serializeErrorResponse(request.id(), error);
    }
    channel.sendText(serialized);
    if (dispatcher.isShuttingDown()) {
      disconnectOnShutdown();
    }
  }

  private static String serializeErrorResponse(Object requestId, Exception error) {
    try {
      return JsonUtil.toJson(
          AgentErrorMapper.errorResponse(requestId, error).toMap(), MAX_MESSAGE_BYTES);
    } catch (ApiException oversizedError) {
      return serializeOversizedFallback(requestId);
    } catch (RuntimeException serializationFailure) {
      try {
        return JsonUtil.toJson(
            AgentErrorMapper.errorResponse(
                    requestId, new IllegalStateException("Internal error", serializationFailure))
                .toMap(),
            MAX_MESSAGE_BYTES);
      } catch (ApiException oversizedError) {
        return serializeOversizedFallback(null);
      }
    }
  }

  private static String serializeOversizedFallback(Object requestId) {
    BridgeError fallback =
        new BridgeError(
            413, "response_too_large", "Response exceeds maximum size", null, Map.of());
    MessageEnvelope.Response response =
        new MessageEnvelope.Response(
            requestId,
            null,
            new MessageEnvelope.RpcError(-32000, fallback.message(), fallback.toMap()));
    try {
      return JsonUtil.toJson(response.toMap(), MAX_MESSAGE_BYTES);
    } catch (ApiException oversizedId) {
      MessageEnvelope.Response nullIdResponse =
          new MessageEnvelope.Response(
              null,
              null,
              new MessageEnvelope.RpcError(-32000, fallback.message(), fallback.toMap()));
      return JsonUtil.toJson(nullIdResponse.toMap(), MAX_MESSAGE_BYTES);
    }
  }

  private void handleNotification(MessageEnvelope.Notification notification) {
    try {
      dispatcher.dispatch(notification.method(), notification.params());
    } catch (Exception ignored) {
      return;
    }
    if (dispatcher.isShuttingDown()) {
      disconnectOnShutdown();
    }
  }

  private void disconnectOnShutdown() {
    try {
      disconnectAction.run();
    } catch (RuntimeException failure) {
      AgentClient.logTransportError("WebSocket shutdown disconnect failed", failure);
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
