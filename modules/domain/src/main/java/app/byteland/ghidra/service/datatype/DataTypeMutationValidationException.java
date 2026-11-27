package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.DomainException;
import java.io.Serial;
import java.util.Objects;

/**
 * Signals a domain validation error on a data type mutation request field.
 */
public final class DataTypeMutationValidationException extends IllegalArgumentException
    implements DomainException {
  @Serial
  private static final long serialVersionUID = 1L;

  /** Field path or JSON pointer that failed validation. */
  private final String validationTarget;

  /**
   * Creates a validation exception for a target field without a root cause.
   *
   * @param target field path or JSON pointer that failed validation
   * @param message human-readable validation error message
   */
  public DataTypeMutationValidationException(String target, String message) {
    this(target, message, null);
  }

  /**
   * Creates a validation exception for a target field with an optional root cause.
   *
   * @param target field path or JSON pointer that failed validation
   * @param message human-readable validation error message
   * @param cause root cause exception, or {@code null}
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
