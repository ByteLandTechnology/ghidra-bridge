package app.byteland.ghidra.service.analysis;

import java.time.Instant;

/**
 * Snapshot of Ghidra auto-analysis state and task progress.
 *
 * @param kind source origin of the analysis task
 * @param status current lifecycle status of the task
 * @param analyzed true after analysis of the program
 * @param taskId identifier for the active task
 * @param startedAt timestamp when task started
 * @param finishedAt timestamp when task finished
 * @param progress completion percentage from 0 to 100, or null if unknown
 * @param message current human-readable phase or status message, or null if unavailable
 * @param error terminal failure description when status is failed, or null otherwise
 */
public record AnalysisResource(
    Kind kind,
    Status status,
    boolean analyzed,
    String taskId,
    Instant startedAt,
    Instant finishedAt,
    Double progress,
    String message,
    String error) {
  /**
   * Represents the initiator of the analysis task.
   */
  public enum Kind {
    GHIDRA,
    BRIDGE
  }

  /**
   * Lifecycle execution status of the analysis task.
   */
  public enum Status {
    IDLE,
    RUNNING,
    COMPLETED,
    CANCELLED,
    FAILED
  }
}
