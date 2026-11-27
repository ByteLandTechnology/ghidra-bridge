package app.byteland.ghidra.service.program;

import java.util.List;
import java.util.Objects;

/**
 * Result of an undo or redo operation on the active program.
 */
public record ProgramUndoRedoResult(
    String action,
    String transactionName,
    boolean canUndo,
    boolean canRedo,
    String undoName,
    String redoName,
    List<String> undoList,
    List<String> redoList) {
  public ProgramUndoRedoResult {
    Objects.requireNonNull(action, "action");
    Objects.requireNonNull(transactionName, "transactionName");
    undoList = undoList == null ? List.of() : List.copyOf(undoList);
    redoList = redoList == null ? List.of() : List.copyOf(redoList);
  }
}
