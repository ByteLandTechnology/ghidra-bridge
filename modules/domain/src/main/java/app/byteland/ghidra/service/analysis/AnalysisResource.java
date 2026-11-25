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
 */
public record AnalysisResource(
    Kind kind,
    Status status,
    boolean analyzed,
    String taskId,
    Instant startedAt,
    Instant finishedAt,
    Double progress) {
  /**
   * Represents the initiator of the analysis task.
   */
  public enum Kind {
    /** Analysis started outside the bridge by Ghidra itself. */
    GHIDRA,
    /** Analysis started through the bridge API. */
    BRIDGE
  }

  /**
   * Lifecycle execution status of the analysis task.
   */
  public enum Status {
    /** No analysis task is active or recorded. */
    IDLE,
    /** Background analysis is currently running. */
    RUNNING,
    /** Most recent bridge analysis task finished normally. */
    COMPLETED,
    /** Most recent bridge analysis task was cancelled. */
    CANCELLED,
    /** Most recent bridge analysis task terminated with an error. */
    FAILED
  }
}
