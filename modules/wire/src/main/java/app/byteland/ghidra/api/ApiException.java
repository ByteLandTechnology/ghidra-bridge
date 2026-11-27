package app.byteland.ghidra.api;

import java.io.Serial;

/**
 * Represents a structured API error with HTTP status and JSON pointer.
 */
public final class ApiException extends RuntimeException {
  @Serial
  private static final long serialVersionUID = 1L;

  /** HTTP-aligned error status code in {@code 400..599}. */
  private final int httpStatus;
  private final transient BridgeError bridgeError;

  /**
   * Creates an API exception with empty structured error details.
   *
   * @param status HTTP-aligned status code in {@code 400..599}
   * @param code snake_case error code
   * @param message human-readable error message
   * @param target optional JSON pointer to the invalid input field
   */
  public ApiException(int status, String code, String message, String target) {
    this(status, new BridgeError(status, code, message, target, java.util.Map.of()));
  }

  /**
   * Creates an API exception from a structured {@link BridgeError}.
   *
   * @param status HTTP-aligned status code equal to {@code error.status()}
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
   * Returns the HTTP-aligned status code.
   *
   * @return status code in {@code 400..599}
   */
  public int status() {
    return httpStatus;
  }

  /**
   * Returns the structured bridge error payload.
   *
   * @return bridge error value, or {@code null} after Java deserialization
   */
  public BridgeError error() {
    return bridgeError;
  }

  /**
   * Creates a {@code 400} bad-request exception.
   *
   * @param reason snake_case error code
   * @param message human-readable error message
   * @param target optional JSON pointer to the invalid input field
   * @return bad-request exception
   */
  public static ApiException badRequest(String reason, String message, String target) {
    return new ApiException(400, reason, message, target);
  }
}
