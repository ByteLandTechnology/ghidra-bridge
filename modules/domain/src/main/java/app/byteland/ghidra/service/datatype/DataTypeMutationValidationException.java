package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/**
 * Indicates invalid input for a data type create or patch request.
 */
public final class DataTypeMutationValidationException extends IllegalArgumentException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /**
   * Validation failure target field or path.
   *
   * @serial
   */
  private final String validationTarget;

  /**
   * Creates a validation exception for a target field and message.
   *
   * @param target validation target field or path
   * @param message validation error message
   */
  public DataTypeMutationValidationException(String target, String message) {
    this(target, message, null);
  }

  /**
   * Creates a validation exception for a target field, message, and cause.
   *
   * @param target validation target field or path
   * @param message validation error message
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
