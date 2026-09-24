package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

public final class GlobalVariableConflictException extends RuntimeException
    implements DomainException {
  private static final long serialVersionUID = 1L;
  private final String errorCode;
  private final String errorTarget;

  public GlobalVariableConflictException(String code, String target, String message) {
    this(code, target, message, null);
  }

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
