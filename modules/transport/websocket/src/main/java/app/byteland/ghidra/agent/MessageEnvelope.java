package app.byteland.ghidra.agent;

import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.api.ApiException;
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
      params = params == null ? Map.of() : Map.copyOf(params);
    }

    @Override
    public Map<String, Object> toMap() {
      return new LinkedHashMap<>(
          Map.of(
              JsonRpc.VERSION,
              JsonRpc.VERSION_VALUE,
              JsonRpc.ID,
              id,
              JsonRpc.METHOD,
              method,
              JsonRpc.PARAMS,
              params));
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
      params = params == null ? Map.of() : Map.copyOf(params);
    }

    @Override
    public Map<String, Object> toMap() {
      return new LinkedHashMap<>(
          Map.of(
              JsonRpc.VERSION,
              JsonRpc.VERSION_VALUE,
              JsonRpc.METHOD,
              method,
              JsonRpc.PARAMS,
              params));
    }
  }

  record RpcError(int code, String message, Map<String, Object> data) {
    public RpcError {
      if (message == null || message.isBlank())
        throw new IllegalArgumentException("message is required");
      data = data == null ? Map.of() : Map.copyOf(data);
    }

    Map<String, Object> toMap() {
      return Map.of(JsonRpc.CODE, code, JsonRpc.MESSAGE, message, JsonRpc.DATA, data);
    }
  }

  static MessageEnvelope fromMap(Map<String, Object> map) {
    if (map == null) throw invalid("message must be an object", "/");
    if (!JsonRpc.isVersion(map.get(JsonRpc.VERSION))) {
      throw invalid("jsonrpc must equal 2.0", "/" + JsonRpc.VERSION);
    }
    if (map.containsKey(JsonRpc.METHOD)) {
      String method = required(map, JsonRpc.METHOD, String.class);
      Map<String, Object> params = params(map);
      if (map.containsKey(JsonRpc.ID)) {
        exact(
            map,
            Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.METHOD, JsonRpc.PARAMS),
            Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.METHOD));
        return new Request(requiredId(map.get(JsonRpc.ID)), method, params);
      }
      exact(
          map,
          Set.of(JsonRpc.VERSION, JsonRpc.METHOD, JsonRpc.PARAMS),
          Set.of(JsonRpc.VERSION, JsonRpc.METHOD));
      return new Notification(method, params);
    }
    Set<String> responseFields =
        map.containsKey(JsonRpc.ERROR)
            ? Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.ERROR)
            : Set.of(JsonRpc.VERSION, JsonRpc.ID, JsonRpc.RESULT);
    exact(map, responseFields, responseFields);
    Object id = map.get(JsonRpc.ID);
    if (id != null) requiredId(id);
    if (map.containsKey(JsonRpc.ERROR))
      return new Response(id, null, parseError(map.get(JsonRpc.ERROR)));
    return new Response(id, map.get(JsonRpc.RESULT), null);
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
    Map<String, Object> map = (Map<String, Object>) raw;
    exact(
        map,
        Set.of(JsonRpc.CODE, JsonRpc.MESSAGE, JsonRpc.DATA),
        Set.of(JsonRpc.CODE, JsonRpc.MESSAGE));
    Object code = map.get(JsonRpc.CODE);
    if (!(code instanceof Number number))
      throw invalid("error code must be an integer", "/" + JsonRpc.ERROR + "/" + JsonRpc.CODE);
    return new RpcError(
        number.intValue(),
        required(map, JsonRpc.MESSAGE, String.class),
        map.containsKey(JsonRpc.DATA)
            ? params(Map.of(JsonRpc.PARAMS, map.get(JsonRpc.DATA)))
            : Map.of());
  }

  private static void exact(Map<String, Object> map, Set<String> allowed, Set<String> required) {
    for (String key : map.keySet())
      if (!allowed.contains(key)) throw invalid("unknown field: " + key, "/" + key);
    for (String key : required)
      if (!map.containsKey(key)) throw invalid(key + " is required", "/" + key);
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
    if (value instanceof Number) return value;
    throw invalid("id must be a string or number", "/id");
  }

  private static ApiException invalid(String message, String target) {
    return ApiException.badRequest("invalid_json_rpc", message, target);
  }
}
