package app.byteland.ghidra.service.program;

import app.byteland.ghidra.service.DomainException;
import java.util.Objects;

/**
 * Reports an invalid program undo or redo state transition.
 */
public final class ProgramHistoryConflictException extends RuntimeException
    implements DomainException {
  private static final long serialVersionUID = 1L;
  private final String errorCode;
  private final String errorTarget;

  public ProgramHistoryConflictException(String code, String target, String message) {
    super(message);
    this.errorCode = Objects.requireNonNull(code, "code");
    this.errorTarget = target;
  }

  public static ProgramHistoryConflictException nothingToUndo() {
    return new ProgramHistoryConflictException(
        "nothing_to_undo", "/method", "no committed transaction is available to undo");
  }

  public static ProgramHistoryConflictException nothingToRedo() {
    return new ProgramHistoryConflictException(
        "nothing_to_redo", "/method", "no undone transaction is available to redo");
  }

  public static ProgramHistoryConflictException transactionInProgress() {
    return new ProgramHistoryConflictException(
        "transaction_in_progress", "/method", "a program transaction is open");
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
