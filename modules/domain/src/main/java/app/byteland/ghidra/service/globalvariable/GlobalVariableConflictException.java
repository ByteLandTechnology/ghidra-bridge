package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/**
 * Signals a {@code 409} conflict on a global variable create or update operation.
 */
public final class GlobalVariableConflictException extends RuntimeException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /** Machine-readable snake_case conflict error code. */
  private final String errorCode;

  /** Field path or JSON pointer associated with the conflict. */
  private final String errorTarget;

  /**
   * Creates a conflict exception without a root cause.
   *
   * @param code snake_case conflict error code
   * @param target field path or JSON pointer associated with the conflict
   * @param message human-readable conflict description
   */
  public GlobalVariableConflictException(String code, String target, String message) {
    this(code, target, message, null);
  }

  /**
   * Creates a conflict exception with an optional root cause.
   *
   * @param code snake_case conflict error code
   * @param target field path or JSON pointer associated with the conflict
   * @param message human-readable conflict description
   * @param cause root cause exception, or {@code null}
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
