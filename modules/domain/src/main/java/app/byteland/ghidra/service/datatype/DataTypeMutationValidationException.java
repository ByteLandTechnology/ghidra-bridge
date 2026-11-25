package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/** Signals invalid input for a data type create or patch operation. */
public final class DataTypeMutationValidationException extends IllegalArgumentException
    implements DomainException {
  private static final long serialVersionUID = 1L;

  /** Target identifier of the validation failure. */
  private final String validationTarget;

  /**
   * Creates a validation exception for the target field or resource.
   *
   * @param target validation target identifier
   * @param message detail message
   */
  public DataTypeMutationValidationException(String target, String message) {
    this(target, message, null);
  }

  /**
   * Creates a validation exception for the target field or resource with a cause.
   *
   * @param target validation target identifier
   * @param message detail message
   * @param cause underlying failure cause, or {@code null}
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
