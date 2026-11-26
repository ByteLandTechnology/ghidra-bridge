package app.byteland.ghidra.api;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class JsonValueCodec implements JsonCodec<Object> {
  private static final int MAX_CACHED_PROJECTIONS = 256;

  private final Map<String, Object> valueSchema;
  private final Map<Set<String>, Map<String, Object>> projectedSchemas =
      new ConcurrentHashMap<>();

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
    return validateOutput(value, valueSchema);
  }

  Object encode(Object value, Set<String> projectedFields) {
    if (projectedFields == null) {
      return validateOutput(value, valueSchema);
    }
    return validateOutput(value, projectedSchema(projectedFields));
  }

  Map<String, Object> projectedSchema(Set<String> projectedFields) {
    Map<String, Object> cached = projectedSchemas.get(projectedFields);
    if (cached != null) {
      return cached;
    }
    Map<String, Object> derived = WireSchema.projectOutput(valueSchema, projectedFields);
    if (projectedSchemas.size() < MAX_CACHED_PROJECTIONS) {
      projectedSchemas.putIfAbsent(Set.copyOf(projectedFields), derived);
    }
    return derived;
  }

  static Object validateOutput(Object value, Map<String, Object> schema) {
    try {
      WireSchema.validate(value, schema, "/result");
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
