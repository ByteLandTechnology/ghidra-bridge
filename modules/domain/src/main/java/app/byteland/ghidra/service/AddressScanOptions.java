package app.byteland.ghidra.service;

/**
 * Contains range limits and time limits for address scans.
 *
 * @param start optional first memory address
 * @param end optional last memory address
 * @param timeoutMs maximum time in milliseconds
 */
public record AddressScanOptions(String start, String end, Integer timeoutMs) {
  /** Default scan time limit in milliseconds. */
  public static final int DEFAULT_TIMEOUT_MS = 1000;

  /** Minimum scan time limit in milliseconds. */
  public static final int MIN_TIMEOUT_MS = 100;

  /** Maximum scan time limit in milliseconds. */
  public static final int MAX_TIMEOUT_MS = 60_000;

  /**
   * Creates address scan options from optional range bounds and timeout.
   *
   * @param start optional first memory address
   * @param end optional last memory address
   * @param timeoutMs optional maximum scan time in milliseconds
   * @return configured address scan options
   */
  public static AddressScanOptions of(String start, String end, Integer timeoutMs) {
    return new AddressScanOptions(start, end, timeoutMs);
  }
}
