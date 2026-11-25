package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/** Signals a state conflict when creating, updating, or deleting a global variable. */
public final class GlobalVariableConflictException extends RuntimeException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /** Domain error code describing the conflict. */
  private final String errorCode;

  /** Target address or symbol identifier associated with the conflict. */
  private final String errorTarget;

  /**
   * Creates a global variable conflict exception.
   *
   * @param code domain error code
   * @param target conflicting address or symbol target
   * @param message detail message
   */
  public GlobalVariableConflictException(String code, String target, String message) {
    this(code, target, message, null);
  }

  /**
   * Creates a global variable conflict exception with a cause.
   *
   * @param code domain error code
   * @param target conflicting address or symbol target
   * @param message detail message
   * @param cause underlying failure cause, or {@code null}
   */
  public GlobalVariableConflictException(
      String code, String target, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = Objects.requireNonNull(code, "code");
    this.errorTarget = Objects.requireNonNull(target, "target");
  }

  @Override
  public int status() {
    return 409;
  }

  @Override
  public String code() {
    return errorCode;
  }

  @Override
  public String target() {
    return errorTarget;
  }
}
