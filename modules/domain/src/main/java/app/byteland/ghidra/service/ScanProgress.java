package app.byteland.ghidra.service;

/**
 * Tracks the progress of cooperative memory scans.
 *
 * @param kind scan classification
 * @param requestedStart lower address bound of query
 * @param requestedEnd upper address bound of query
 * @param scannedStart first address visited in this page, in scan direction
 * @param scannedEnd last address visited in this page, in scan direction
 * @param complete true after the scan covers the full requested range
 * @param stopReason termination cause
 * @param elapsedMs scan time in milliseconds
 */
public record ScanProgress(
    Kind kind,
    String requestedStart,
    String requestedEnd,
    String scannedStart,
    String scannedEnd,
    boolean complete,
    StopReason stopReason,
    long elapsedMs) {
  public ScanProgress {
    if (kind == null) throw new IllegalArgumentException("kind is required");
    if (stopReason == null) throw new IllegalArgumentException("stopReason is required");
    if (elapsedMs < 0) throw new IllegalArgumentException("elapsedMs must not be negative");
    if (complete != (stopReason == StopReason.COMPLETED)) {
      throw new IllegalArgumentException("complete and stopReason disagree");
    }
  }

  /**
   * Scan classification category.
   */
  public enum Kind {
    ADDRESS
  }

  /**
   * Cause of scan loop termination.
   */
  public enum StopReason {
    COMPLETED,
    LIMIT,
    TIMEOUT
  }
}
