package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/**
 * Signals a conflict when creating, updating, or deleting a global variable.
 */
public final class GlobalVariableConflictException extends RuntimeException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /** Machine-readable conflict error code. */
  private final String errorCode;

  /** Target field or resource associated with the conflict. */
  private final String errorTarget;

  /**
   * Creates a global variable conflict exception.
   *
   * @param code machine-readable conflict error code
   * @param target conflicting field or resource target
   * @param message human-readable conflict description
   */
  public GlobalVariableConflictException(String code, String target, String message) {
    this(code, target, message, null);
  }

  /**
   * Creates a global variable conflict exception with an underlying cause.
   *
   * @param code machine-readable conflict error code
   * @param target conflicting field or resource target
   * @param message human-readable conflict description
   * @param cause underlying conflict cause
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
