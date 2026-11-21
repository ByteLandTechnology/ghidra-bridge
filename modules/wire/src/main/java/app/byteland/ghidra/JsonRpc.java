package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Constants and envelope builders for JSON-RPC 2.0 messages.
 */
public final class JsonRpc {
  /** Supported JSON-RPC protocol version string. */
  public static final String VERSION_VALUE = "2.0";

  /** Envelope field name for the JSON-RPC version. */
  public static final String VERSION = "jsonrpc";

  /** Envelope field name for the request or response identifier. */
  public static final String ID = "id";

  /** Envelope field name for the request method name. */
  public static final String METHOD = "method";

  /** Envelope field name for request parameters. */
  public static final String PARAMS = "params";

  /** Envelope field name for a successful response payload. */
  public static final String RESULT = "result";

  /** Envelope field name for an error response object. */
  public static final String ERROR = "error";

  /** Error object field name for the numeric error code. */
  public static final String CODE = "code";

  /** Error object field name for the error message string. */
  public static final String MESSAGE = "message";

  /** Error object field name for structured error details. */
  public static final String DATA = "data";

  private JsonRpc() {}

  /**
   * Checks whether a value equals {@link #VERSION_VALUE}.
   *
   * @param value candidate version value
   * @return {@code true} if {@code value} is {@code "2.0"}
   */
  public static boolean isVersion(Object value) {
    return VERSION_VALUE.equals(value);
  }

  /**
   * Builds a JSON-RPC 2.0 success response map.
   *
   * @param id request identifier
   * @param result response result value
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
   * Builds a JSON-RPC 2.0 error response map without structured data.
   *
   * @param id request identifier, or {@code null}
   * @param code JSON-RPC numeric error code
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
   * @param id request identifier, or {@code null}
   * @param code JSON-RPC numeric error code
   * @param message human-readable error message
   * @param data structured error metadata
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
