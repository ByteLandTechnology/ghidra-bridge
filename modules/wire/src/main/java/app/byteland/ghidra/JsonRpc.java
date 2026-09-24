package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;

public final class JsonRpc {
  public static final String VERSION_VALUE = "2.0";
  public static final String VERSION = "jsonrpc";
  public static final String ID = "id";
  public static final String METHOD = "method";
  public static final String PARAMS = "params";
  public static final String RESULT = "result";
  public static final String ERROR = "error";
  public static final String CODE = "code";
  public static final String MESSAGE = "message";
  public static final String DATA = "data";

  private JsonRpc() {}

  public static boolean isVersion(Object value) {
    return VERSION_VALUE.equals(value);
  }

  public static Map<String, Object> success(Object id, Object result) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(VERSION, VERSION_VALUE);
    payload.put(ID, id);
    payload.put(RESULT, result);
    return payload;
  }

  public static Map<String, Object> errorResponse(Object id, int code, String message) {
    Map<String, Object> error = new LinkedHashMap<>();
    error.put(CODE, code);
    error.put(MESSAGE, message);
    return errorEnvelope(id, error);
  }

  public static Map<String, Object> errorResponse(
      Object id, int code, String message, Map<String, Object> data) {
    Map<String, Object> error = new LinkedHashMap<>();
    error.put(CODE, code);
    error.put(MESSAGE, message);
    error.put(DATA, data);
    return errorEnvelope(id, error);
  }

  private static Map<String, Object> errorEnvelope(Object id, Map<String, Object> error) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(VERSION, VERSION_VALUE);
    payload.put(ID, id);
    payload.put(ERROR, error);
    return payload;
  }
}
