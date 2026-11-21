package app.byteland.ghidra.service;

/**
 * Contains range limits and time limits for address scans.
 *
 * @param start optional first memory address
 * @param end optional last memory address
 * @param timeoutMs maximum time in milliseconds
 */
public record AddressScanOptions(
    String start, String end, Integer timeoutMs, String startTarget, String endTarget) {
  public static final int DEFAULT_TIMEOUT_MS = 1000;
  public static final int MIN_TIMEOUT_MS = 100;
  public static final int MAX_TIMEOUT_MS = 60_000;
  public static final String DEFAULT_START_TARGET = "/scan/range/start";
  public static final String DEFAULT_END_TARGET = "/scan/range/end";

  public AddressScanOptions {
    startTarget = startTarget == null ? DEFAULT_START_TARGET : startTarget;
    endTarget = endTarget == null ? DEFAULT_END_TARGET : endTarget;
  }

  public AddressScanOptions(String start, String end, Integer timeoutMs) {
    this(start, end, timeoutMs, DEFAULT_START_TARGET, DEFAULT_END_TARGET);
  }

  public static AddressScanOptions of(String start, String end, Integer timeoutMs) {
    return new AddressScanOptions(start, end, timeoutMs);
  }
}
