package app.byteland.ghidra.agent;

import app.byteland.ghidra.api.ApiFailures;

final class AgentErrorMapper {
  private AgentErrorMapper() {}

  static MessageEnvelope.Response errorResponse(Object requestId, Exception exception) {
    ApiFailures.Failure failure = ApiFailures.normalize(exception);
    return new MessageEnvelope.Response(
        requestId,
        null,
        new MessageEnvelope.RpcError(-32000, failure.error().message(), failure.error().toMap()));
  }
}
