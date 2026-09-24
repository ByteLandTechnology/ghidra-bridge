package app.byteland.ghidra.adapter.ghidra.decompilation;

final class GhidraTimeout {
  private static final long MILLISECONDS_PER_SECOND = 1_000L;

  private GhidraTimeout() {}

  static int secondsForMilliseconds(int timeoutMilliseconds) {
    return Math.toIntExact(Math.ceilDiv((long) timeoutMilliseconds, MILLISECONDS_PER_SECOND));
  }
}
