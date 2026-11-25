package app.byteland.ghidra.api;

/**
 * Represents a structured API error with HTTP status and JSON pointer.
 */
public final class ApiException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  /** HTTP-equivalent status code in {@code 400..599}. */
  private final int httpStatus;

  private final transient BridgeError bridgeError;

  /**
   * Creates an {@link ApiException} with empty error details.
   *
   * @param status HTTP-equivalent status code
   * @param code snake_case error code
   * @param message human-readable error message
   * @param target optional JSON Pointer identifying the offending field
   */
  public ApiException(int status, String code, String message, String target) {
    this(status, new BridgeError(status, code, message, target, java.util.Map.of()));
  }

  /**
   * Creates an {@link ApiException} wrapping a {@link BridgeError}.
   *
   * @param status HTTP-equivalent status code matching {@code error.status()}
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
   * Returns the HTTP-equivalent status code.
   *
   * @return status code in {@code 400..599}
   */
  public int status() {
    return httpStatus;
  }

  /**
   * Returns the structured {@link BridgeError} payload.
   *
   * @return bridge error payload
   */
  public BridgeError error() {
    return bridgeError;
  }

  /**
   * Creates a {@code 400} bad-request {@link ApiException}.
   *
   * @param reason snake_case error code
   * @param message human-readable error message
   * @param target optional JSON Pointer identifying the offending field
   * @return {@code 400} API exception
   */
  public static ApiException badRequest(String reason, String message, String target) {
    return new ApiException(400, reason, message, target);
  }
}
