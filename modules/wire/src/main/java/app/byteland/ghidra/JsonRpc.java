package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Defines JSON-RPC 2.0 envelope field names and response builders.
 */
public final class JsonRpc {
  /** JSON-RPC protocol version literal ({@code "2.0"}). */
  public static final String VERSION_VALUE = "2.0";
  /** Envelope field name for the JSON-RPC protocol version. */
  public static final String VERSION = "jsonrpc";
  /** Envelope field name for the request or response identifier. */
  public static final String ID = "id";
  /** Envelope field name for the invoked method name. */
  public static final String METHOD = "method";
  /** Envelope field name for the method parameter object. */
  public static final String PARAMS = "params";
  /** Envelope field name for a successful result payload. */
  public static final String RESULT = "result";
  /** Envelope field name for a structured error object. */
  public static final String ERROR = "error";
  /** Error object field name for the numeric JSON-RPC error code. */
  public static final String CODE = "code";
  /** Error object field name for the human-readable error message. */
  public static final String MESSAGE = "message";
  /** Error object field name for optional structured error details. */
  public static final String DATA = "data";

  private JsonRpc() {}

  /**
   * Returns {@code true} when {@code value} equals {@link #VERSION_VALUE}.
   *
   * @param value candidate protocol version value
   * @return {@code true} if {@code value} is {@code "2.0"}
   */
  public static boolean isVersion(Object value) {
    return VERSION_VALUE.equals(value);
  }

  /**
   * Builds a JSON-RPC 2.0 success response envelope.
   *
   * @param id request identifier echoed in the response
   * @param result method result value
   * @return mutable JSON-RPC success envelope map
   */
  public static Map<String, Object> success(Object id, Object result) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put(VERSION, VERSION_VALUE);
    payload.put(ID, id);
    payload.put(RESULT, result);
    return payload;
  }

  /**
   * Builds a JSON-RPC 2.0 error response envelope without a {@code data} field.
   *
   * @param id request identifier, or {@code null} when unknown
   * @param code numeric JSON-RPC error code
   * @param message human-readable error summary
   * @return mutable JSON-RPC error envelope map
   */
  public static Map<String, Object> errorResponse(Object id, int code, String message) {
    Map<String, Object> error = new LinkedHashMap<>();
    error.put(CODE, code);
    error.put(MESSAGE, message);
    return errorEnvelope(id, error);
  }

  /**
   * Builds a JSON-RPC 2.0 error response envelope with structured {@code data}.
   *
   * @param id request identifier, or {@code null} when unknown
   * @param code numeric JSON-RPC error code
   * @param message human-readable error summary
   * @param data structured error metadata map
   * @return mutable JSON-RPC error envelope map
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
