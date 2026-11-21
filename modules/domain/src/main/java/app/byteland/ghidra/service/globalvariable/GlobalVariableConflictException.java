package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/**
 * Indicates a conflict with an existing instruction, symbol, or data item during a global variable
 * mutation.
 */
public final class GlobalVariableConflictException extends RuntimeException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /**
   * Machine-readable conflict error code.
   *
   * @serial
   */
  private final String errorCode;

  /**
   * Conflicting address or symbol target.
   *
   * @serial
   */
  private final String errorTarget;

  /**
   * Creates a conflict exception with code, target, and message.
   *
   * @param code machine-readable conflict code
   * @param target conflicting address or symbol name
   * @param message human-readable conflict description
   */
  public GlobalVariableConflictException(String code, String target, String message) {
    this(code, target, message, null);
  }

  /**
   * Creates a conflict exception with code, target, message, and cause.
   *
   * @param code machine-readable conflict code
   * @param target conflicting address or symbol name
   * @param message human-readable conflict description
   * @param cause underlying failure cause
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
