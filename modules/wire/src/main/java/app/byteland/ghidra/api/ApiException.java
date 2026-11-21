package app.byteland.ghidra.api;

/**
 * Represents a structured API error with HTTP status and JSON pointer.
 */
public final class ApiException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  /**
   * HTTP status code associated with this API error.
   *
   * @serial
   */
  private final int httpStatus;
  private final transient BridgeError bridgeError;

  /**
   * Creates an API exception from status, code, message, and optional JSON pointer target.
   *
   * @param status HTTP status code
   * @param code machine-readable error code
   * @param message human-readable error message
   * @param target optional JSON pointer target
   */
  public ApiException(int status, String code, String message, String target) {
    this(status, new BridgeError(status, code, message, target, java.util.Map.of()));
  }

  /**
   * Creates an API exception wrapping a structured {@link BridgeError}.
   *
   * @param status HTTP status code matching {@code error.status()}
   * @param error structured bridge error payload
   */
  public ApiException(int status, BridgeError error) {
    super(error.message());
    this.httpStatus = status;
    this.bridgeError = error;
    if (status != error.status()) {
      throw new IllegalArgumentException("exception status must match error status");
    }
  }

  /**
   * Returns the HTTP status code.
   *
   * @return HTTP status code
   */
  public int status() {
    return httpStatus;
  }

  /**
   * Returns the structured bridge error payload.
   *
   * @return structured bridge error
   */
  public BridgeError error() {
    return bridgeError;
  }

  /**
   * Creates a 400 Bad Request {@link ApiException}.
   *
   * @param reason machine-readable error code
   * @param message human-readable error message
   * @param target optional JSON pointer target
   * @return 400 Bad Request exception
   */
  public static ApiException badRequest(String reason, String message, String target) {
    return new ApiException(400, reason, message, target);
  }
}
