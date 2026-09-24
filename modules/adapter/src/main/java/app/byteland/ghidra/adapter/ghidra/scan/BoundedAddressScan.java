package app.byteland.ghidra.adapter.ghidra.scan;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import java.util.ArrayList;
import java.util.List;
import java.util.function.LongSupplier;

public final class BoundedAddressScan<T> {
  private static final int MIN_RESULT_LIMIT = 1;
  private static final int MAX_RESULT_LIMIT = Page.MAX_LIMIT;
  private static final int MIN_TIMEOUT_MILLIS = 1;
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;

  private final int limit;
  private final long timeoutNanos;
  private final String requestedStart;
  private final String requestedEnd;
  private final LongSupplier nanoTime;
  private final long startedNanos;
  private final List<T> items = new ArrayList<>();

  private String scannedStart;
  private String scannedEnd;
  private String lastCursor;
  private ScanProgress.StopReason stopReason;

  public static <T> BoundedAddressScan<T> start(
      int limit, int timeoutMs, String requestedStart, String requestedEnd) {
    return new BoundedAddressScan<>(
        limit, timeoutMs, requestedStart, requestedEnd, System::nanoTime);
  }

  BoundedAddressScan(
      int limit, int timeoutMs, String requestedStart, String requestedEnd, LongSupplier nanoTime) {
    if (limit < MIN_RESULT_LIMIT || limit > MAX_RESULT_LIMIT) {
      throw new IllegalArgumentException(
          "limit must be in " + MIN_RESULT_LIMIT + ".." + MAX_RESULT_LIMIT);
    }
    if (timeoutMs < MIN_TIMEOUT_MILLIS) {
      throw new IllegalArgumentException("timeoutMs must be positive");
    }
    this.limit = limit;
    this.timeoutNanos = timeoutMs * NANOS_PER_MILLISECOND;
    this.requestedStart = requestedStart;
    this.requestedEnd = requestedEnd;
    this.nanoTime = nanoTime;
    this.startedNanos = nanoTime.getAsLong();
  }

  public void visit(String address, String cursor, T matchingItem) {
    if (stopped()) throw new IllegalStateException("scan is already stopped");
    if (address == null || cursor == null) {
      throw new IllegalArgumentException("address and cursor are required");
    }
    if (scannedStart == null) scannedStart = address;
    scannedEnd = address;
    lastCursor = cursor;
    if (matchingItem != null) items.add(matchingItem);

    if (elapsedNanos() >= timeoutNanos) {
      stopReason = ScanProgress.StopReason.TIMEOUT;
    } else if (items.size() >= limit) {
      stopReason = ScanProgress.StopReason.LIMIT;
    }
  }

  public boolean stopped() {
    return stopReason != null;
  }

  public Page<T> finish() {
    ScanProgress.StopReason reason =
        stopReason == null ? ScanProgress.StopReason.COMPLETED : stopReason;
    boolean complete = reason == ScanProgress.StopReason.COMPLETED;
    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            requestedStart,
            requestedEnd,
            scannedStart,
            scannedEnd,
            complete,
            reason,
            elapsedMillis());
    return Page.scanned(items, limit, complete ? null : lastCursor, progress);
  }

  private long elapsedNanos() {
    return Math.max(0, nanoTime.getAsLong() - startedNanos);
  }

  private long elapsedMillis() {
    return elapsedNanos() / NANOS_PER_MILLISECOND;
  }
}
