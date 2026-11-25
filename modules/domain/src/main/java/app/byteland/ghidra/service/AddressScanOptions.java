package app.byteland.ghidra.service;

/**
 * Contains range limits and time limits for address scans.
 *
 * @param start optional first memory address
 * @param end optional last memory address
 * @param timeoutMs maximum time in milliseconds
 */
public record AddressScanOptions(String start, String end, Integer timeoutMs) {
  /** Default scan time budget in milliseconds. */
  public static final int DEFAULT_TIMEOUT_MS = 1000;
  /** Minimum allowed scan time budget in milliseconds. */
  public static final int MIN_TIMEOUT_MS = 100;
  /** Maximum allowed scan time budget in milliseconds. */
  public static final int MAX_TIMEOUT_MS = 60_000;

  /**
   * Creates an {@link AddressScanOptions} value with optional bounds and timeout.
   *
   * @param start optional inclusive start address, or {@code null}
   * @param end optional inclusive end address, or {@code null}
   * @param timeoutMs optional scan timeout in milliseconds, or {@code null}
   * @return address scan options instance
   */
  public static AddressScanOptions of(String start, String end, Integer timeoutMs) {
    return new AddressScanOptions(start, end, timeoutMs);
  }
}
