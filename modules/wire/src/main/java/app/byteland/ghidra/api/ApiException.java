package app.byteland.ghidra.api;

/**
 * Represents a structured API error with HTTP status and JSON pointer.
 */
public final class ApiException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final int httpStatus;
  private final transient BridgeError bridgeError;

  public ApiException(int status, String code, String message, String target) {
    this(status, new BridgeError(status, code, message, target, java.util.Map.of()));
  }

  public ApiException(int status, BridgeError error) {
    super(error.message());
    this.httpStatus = status;
    this.bridgeError = error;
    if (status != error.status()) {
      throw new IllegalArgumentException("exception status must match error status");
    }
  }

  public int status() {
    return httpStatus;
  }

  public BridgeError error() {
    return bridgeError;
  }

  public static ApiException badRequest(String reason, String message, String target) {
    return new ApiException(400, reason, message, target);
  }
}
