package app.byteland.ghidra.api;

import java.util.Map;
import java.util.Set;

final class JsonValueCodec implements JsonCodec<Object> {
  private final Map<String, Object> valueSchema;

  JsonValueCodec(Map<String, Object> schema) {
    this.valueSchema = Map.copyOf(schema);
  }

  @Override
  public Object decode(Object value, String target) {
    WireSchema.validate(value, valueSchema, target);
    return value;
  }

  @Override
  public Object encode(Object value) {
    return encode(value, null);
  }

  @Override
  public Object encode(Object value, Set<String> projectedFields) {
    try {
      if (projectedFields == null) {
        WireSchema.validate(value, valueSchema, "/result");
      } else {
        WireSchema.validateProjected(value, valueSchema, "/result", projectedFields);
      }
    } catch (ApiException invalidResponse) {
      ApiException translated =
          new ApiException(
              500,
              "invalid_response",
              "handler returned a value that violates its output schema",
              invalidResponse.error().target());
      translated.initCause(invalidResponse);
      throw translated;
    }
    return value;
  }

  @Override
  public Map<String, Object> schema() {
    return valueSchema;
  }
}
