package app.byteland.ghidra.adapter.ghidra.decompilation;

import java.util.concurrent.TimeUnit;

final class GhidraTimeout {
  private static final long MILLISECONDS_PER_SECOND = 1_000L;

  private GhidraTimeout() {}

  static int secondsForMilliseconds(int timeoutMilliseconds) {
    return Math.toIntExact(Math.ceilDiv((long) timeoutMilliseconds, MILLISECONDS_PER_SECOND));
  }

  static long budgetNanos(int timeoutMilliseconds) {
    return TimeUnit.SECONDS.toNanos(secondsForMilliseconds(timeoutMilliseconds));
  }

  static long deadlineNanos(long startedAtNanos, int timeoutMilliseconds) {
    return startedAtNanos + budgetNanos(timeoutMilliseconds);
  }
}
