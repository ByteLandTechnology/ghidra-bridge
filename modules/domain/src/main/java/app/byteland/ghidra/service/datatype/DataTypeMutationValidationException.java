package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

public final class DataTypeMutationValidationException extends IllegalArgumentException
    implements DomainException {
  private static final long serialVersionUID = 1L;
  private final String validationTarget;

  public DataTypeMutationValidationException(String target, String message) {
    this(target, message, null);
  }

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
