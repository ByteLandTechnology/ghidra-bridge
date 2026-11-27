package app.byteland.ghidra.service.program;

import java.util.List;

/**
 * Snapshot of transaction undo and redo state for the active program.
 */
public record ProgramHistoryResource(
    boolean canUndo,
    boolean canRedo,
    String undoName,
    String redoName,
    List<String> undoList,
    List<String> redoList) {
  public ProgramHistoryResource {
    undoList = undoList == null ? List.of() : List.copyOf(undoList);
    redoList = redoList == null ? List.of() : List.copyOf(redoList);
  }
}
