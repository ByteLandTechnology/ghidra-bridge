package app.byteland.ghidra.service;

/**
 * Contains range limits and time limits for address scans.
 *
 * @param start optional first memory address
 * @param end optional last memory address
 * @param timeoutMs maximum time in milliseconds
 */
public record AddressScanOptions(String start, String end, Integer timeoutMs) {
  /** Default cooperative scan timeout in milliseconds. */
  public static final int DEFAULT_TIMEOUT_MS = 1000;

  /** Minimum allowed cooperative scan timeout in milliseconds. */
  public static final int MIN_TIMEOUT_MS = 100;

  /** Maximum allowed cooperative scan timeout in milliseconds. */
  public static final int MAX_TIMEOUT_MS = 60_000;

  /**
   * Creates scan options for an optional start address, end address, and timeout budget.
   *
   * @param start optional inclusive start address
   * @param end optional inclusive end address
   * @param timeoutMs optional timeout budget in milliseconds
   * @return constructed scan options
   */
  public static AddressScanOptions of(String start, String end, Integer timeoutMs) {
    return new AddressScanOptions(start, end, timeoutMs);
  }
}
