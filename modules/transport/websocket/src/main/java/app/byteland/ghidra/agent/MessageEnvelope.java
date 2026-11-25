package app.byteland.ghidra.agent;

import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.api.ApiException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

sealed interface MessageEnvelope
    permits MessageEnvelope.Request, MessageEnvelope.Response, MessageEnvelope.Notification {
  Map<String, Object> toMap();

  record Request(Object id, String method, Map<String, Object> params) implements MessageEnvelope {
    public Request {
      id = requiredId(id);
      method = requiredText(method, JsonRpc.METHOD);
      params =
          params == null
              ? Map.of()
              : Collections.unmodifiableMap(
                  new LinkedHashMap<>(validatedMap(params, "/" + JsonRpc.PARAMS)));
    }

    @Override
    public Map<String, Object> toMap() {
      Map<String, Object> map = new LinkedHashMap<>();
      map.put(JsonRpc.VERSION, JsonRpc.VERSION_VALUE);
      map.put(JsonRpc.ID, id);
      map.put(JsonRpc.METHOD, method);
      map.put(JsonRpc.PARAMS, params);
      return map;
    }
  }

  record Response(Object id, Object result, RpcError error) implements MessageEnvelope {
    public Response {
      if (error != null && result != null) {
        throw invalid("response cannot contain both result and error", "/");
      }
    }

    @Override
    public Map<String, Object> toMap() {
      return error == null
          ? JsonRpc.success(id, result)
          : JsonRpc.errorResponse(id, error.code(), error.message(), error.data());
    }
  }

  record Notification(String method, Map<String, Object> params) implements MessageEnvelope {
    public Notification {
      method = requiredText(method, JsonRpc.METHOD);
      params =
          params == null
              ? Map.of()
              : Collections.unmodifiableMap(
                  new LinkedHashMap<>(validatedMap(params, "/" + JsonRpc.PARAMS)));
    }

    @Override
    public Map<String, Object> toMap() {
      Map<String, Object> map = new LinkedHashMap<>();
      map.put(JsonRpc.VERSION, JsonRpc.VERSION_VALUE);
      map.put(JsonRpc.METHOD, method);
      map.put(JsonRpc.PARAMS, params);
      return map;
    }
  }

  record RpcError(int code, String message, Map<String, Object> data) {
    public RpcError {
      if (message == null || message.isBlank()) {
        throw invalid(
            "error message must not be blank", "/" + JsonRpc.ERROR + "/" + JsonRpc.MESSAGE);
      }
      data =
          data == null
              ? Map.of()
              : Collections.unmodifiableMap(
                  new LinkedHashMap<>(
                      validatedMap(data, "/" + JsonRpc.ERROR + "/" + JsonRpc.DATA)));
    }

    Map<String, Object> toMap() {
      Map<String, Object> map = new LinkedHashMap<>();
      map.put(JsonRpc.CODE, code);
      map.put(JsonRpc.MESSAGE, message);
      map.put(JsonRpc.DATA, data);
      return Collections.unmodifiableMap(map);
    }
  }

  static MessageEnvelope fromMap(Map<String, Object> map) {
    if (map == null) throw invalid("message must be an object", "/");
    Map<String, Object> validated = validatedMap(map, "");
    if (!JsonRpc.isVersion(validated.get(JsonRpc.VERSION))) {
      throw invalid("jsonrpc must equal 2.0", "/" + JsonRpc.VERSION);
    }
    if (validated.containsKey(JsonRpc.METHOD)) {
      String method = required(validated, JsonRpc.METHOD, String.class);
      Map<String, Object> params = params(validated);
      if (validated.containsKey(JsonRpc.ID)) {
        exact(
            validated,
            Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.METHOD, JsonRpc.PARAMS),
            Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.METHOD),
            "");
        return new Request(requiredId(validated.get(JsonRpc.ID)), method, params);
      }
      exact(
          validated,
          Set.of(JsonRpc.VERSION, JsonRpc.METHOD, JsonRpc.PARAMS),
          Set.of(JsonRpc.VERSION, JsonRpc.METHOD),
          "");
      return new Notification(method, params);
    }
    Set<String> responseFields =
        validated.containsKey(JsonRpc.ERROR)
            ? Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.ERROR)
            : Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.RESULT);
    exact(validated, responseFields, responseFields, "");
    Object id = validated.get(JsonRpc.ID);
    if (id != null) requiredId(id);
    if (validated.containsKey(JsonRpc.ERROR))
      return new Response(id, null, parseError(validated.get(JsonRpc.ERROR)));
    return new Response(id, validated.get(JsonRpc.RESULT), null);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> params(Map<String, Object> map) {
    Object params = map.getOrDefault(JsonRpc.PARAMS, Map.of());
    if (!(params instanceof Map<?, ?> object))
      throw invalid("params must be an object", "/" + JsonRpc.PARAMS);
    return (Map<String, Object>) object;
  }

  @SuppressWarnings("unchecked")
  private static RpcError parseError(Object value) {
    if (!(value instanceof Map<?, ?> raw))
      throw invalid("error must be an object", "/" + JsonRpc.ERROR);
    Map<String, Object> map = validatedMap((Map<String, Object>) raw, "/" + JsonRpc.ERROR);
    exact(
        map,
        Set.of(JsonRpc.CODE, JsonRpc.MESSAGE, JsonRpc.DATA),
        Set.of(JsonRpc.CODE, JsonRpc.MESSAGE),
        "/" + JsonRpc.ERROR);
    return new RpcError(
        parseErrorCode(map.get(JsonRpc.CODE)),
        requiredErrorMessage(map.get(JsonRpc.MESSAGE)),
        parseErrorData(map));
  }

  private static int parseErrorCode(Object code) {
    if (code instanceof Byte || code instanceof Short || code instanceof Integer) {
      return ((Number) code).intValue();
    }
    if (code instanceof Long value && value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) {
      return value.intValue();
    }
    throw invalid("error code must be an integer", "/" + JsonRpc.ERROR + "/" + JsonRpc.CODE);
  }

  private static String requiredErrorMessage(Object value) {
    if (!(value instanceof String text)) {
      throw invalid(
          "error message has an invalid type", "/" + JsonRpc.ERROR + "/" + JsonRpc.MESSAGE);
    }
    if (text.isBlank()) {
      throw invalid("error message must not be blank", "/" + JsonRpc.ERROR + "/" + JsonRpc.MESSAGE);
    }
    return text;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> parseErrorData(Map<String, Object> map) {
    if (!map.containsKey(JsonRpc.DATA)) {
      return Map.of();
    }
    Object data = map.get(JsonRpc.DATA);
    if (!(data instanceof Map<?, ?> object)) {
      throw invalid("error data must be an object", "/" + JsonRpc.ERROR + "/" + JsonRpc.DATA);
    }
    return (Map<String, Object>) object;
  }

  private static Map<String, Object> validatedMap(Map<String, Object> map, String pointer) {
    String target = pointer.isEmpty() ? "/" : pointer;
    for (Object key : ((Map<?, ?>) map).keySet()) {
      if (!(key instanceof String)) {
        throw invalid("object keys must be strings", target);
      }
    }
    return map;
  }

  private static void exact(
      Map<String, Object> map, Set<String> allowed, Set<String> required, String prefix) {
    for (String key : map.keySet())
      if (!allowed.contains(key)) throw invalid("unknown field: " + key, prefix + "/" + key);
    for (String key : required)
      if (!map.containsKey(key)) throw invalid(key + " is required", prefix + "/" + key);
  }

  private static <T> T required(Map<String, Object> map, String key, Class<T> type) {
    Object value = map.get(key);
    if (!type.isInstance(value)) throw invalid(key + " has an invalid type", "/" + key);
    return type.cast(value);
  }

  private static String requiredText(String value, String key) {
    if (value == null || value.isBlank()) throw invalid(key + " must not be blank", "/" + key);
    return value;
  }

  private static Object requiredId(Object value) {
    if (value instanceof String text && !text.isBlank()) return text;
    if (value instanceof Double d && !Double.isFinite(d)) {
      throw invalid("id must be a string or number", "/id");
    }
    if (value instanceof Float f && !Float.isFinite(f)) {
      throw invalid("id must be a string or number", "/id");
    }
    if (value instanceof Number) return value;
    throw invalid("id must be a string or number", "/id");
  }

  private static ApiException invalid(String message, String target) {
    return ApiException.badRequest("invalid_json_rpc", message, target);
  }
}
