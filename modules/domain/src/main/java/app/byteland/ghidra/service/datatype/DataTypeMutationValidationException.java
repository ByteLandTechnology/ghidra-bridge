package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/**
 * Signals that a data type mutation request failed domain validation.
 */
public final class DataTypeMutationValidationException extends IllegalArgumentException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /** Target field or resource that failed validation. */
  private final String validationTarget;

  /**
   * Creates a validation exception for a data type mutation target.
   *
   * @param target field or resource target
   * @param message validation error detail
   */
  public DataTypeMutationValidationException(String target, String message) {
    this(target, message, null);
  }

  /**
   * Creates a validation exception for a data type mutation target with a cause.
   *
   * @param target field or resource target
   * @param message validation error detail
   * @param cause underlying failure cause
   */
  public DataTypeMutationValidationException(String target, String message, Throwable cause) {
    super(message, cause);
    validationTarget = Objects.requireNonNull(target, "target");
  }

  @Override
  public int status() {
    return 400;
  }

  @Override
  public String code() {
    return "validation_failed";
  }

  @Override
  public String target() {
    return validationTarget;
  }
}
