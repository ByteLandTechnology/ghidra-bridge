package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Constants and envelope builders for JSON-RPC 2.0 messages.
 */
public final class JsonRpc {
  /** JSON-RPC protocol version string ({@code "2.0"}). */
  public static final String VERSION_VALUE = "2.0";

  /** Envelope field name for the JSON-RPC protocol version. */
  public static final String VERSION = "jsonrpc";

  /** Envelope field name for the request or response correlation identifier. */
  public static final String ID = "id";

  /** Envelope field name for the invoked method name. */
  public static final String METHOD = "method";

  /** Envelope field name for method request parameters. */
  public static final String PARAMS = "params";

  /** Envelope field name for a successful method result. */
  public static final String RESULT = "result";

  /** Envelope field name for an error response object. */
  public static final String ERROR = "error";

  /** Error object field name for the numeric JSON-RPC error code. */
  public static final String CODE = "code";

  /** Error object field name for the human-readable error message. */
  public static final String MESSAGE = "message";

  /** Error object field name for structured error details. */
  public static final String DATA = "data";

  private JsonRpc() {}

  /**
   * Checks whether a field value equals the JSON-RPC 2.0 version string.
   *
   * @param value candidate version field value
   * @return true when {@code value} equals {@code "2.0"}
   */
  public static boolean isVersion(Object value) {
    return VERSION_VALUE.equals(value);
  }

  /**
   * Builds a JSON-RPC 2.0 success response map.
   *
   * @param id request identifier
   * @param result method result payload
   * @return JSON-RPC success envelope
   */
  public static Map<String, Object> success(Object id, Object result) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(VERSION, VERSION_VALUE);
    payload.put(ID, id);
    payload.put(RESULT, result);
    return payload;
  }

  /**
   * Builds a JSON-RPC 2.0 error response map without structured error data.
   *
   * @param id request identifier, or null when unknown
   * @param code JSON-RPC error code
   * @param message human-readable error message
   * @return JSON-RPC error envelope
   */
  public static Map<String, Object> errorResponse(Object id, int code, String message) {
    Map<String, Object> error = new LinkedHashMap<>();
    error.put(CODE, code);
    error.put(MESSAGE, message);
    return errorEnvelope(id, error);
  }

  /**
   * Builds a JSON-RPC 2.0 error response map with structured error data.
   *
   * @param id request identifier, or null when unknown
   * @param code JSON-RPC error code
   * @param message human-readable error message
   * @param data structured error data map
   * @return JSON-RPC error envelope
   */
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
