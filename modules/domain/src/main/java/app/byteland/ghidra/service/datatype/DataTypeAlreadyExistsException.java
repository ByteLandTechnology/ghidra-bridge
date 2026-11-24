package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

public final class DataTypeAlreadyExistsException extends IllegalStateException
    implements DomainException {
  private static final long serialVersionUID = 1L;
  private final String conflictTarget;

  public DataTypeAlreadyExistsException(String target, String message) {
    super(message);
    conflictTarget = Objects.requireNonNull(target, "target");
  }

  @Override
  public int status() {
    return 409;
  }

  @Override
  public String code() {
    return "data_type_exists";
  }

  @Override
  public String target() {
    return conflictTarget;
  }
}
