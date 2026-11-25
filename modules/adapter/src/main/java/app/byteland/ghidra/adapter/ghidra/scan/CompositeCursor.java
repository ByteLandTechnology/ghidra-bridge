package app.byteland.ghidra.adapter.ghidra.scan;

/**
 * Two-part pagination cursor combining a canonical address and a secondary sort key.
 *
 * @param address canonical address component
 * @param secondary secondary tie-breaker component
 */
public record CompositeCursor(String address, String secondary) {
  /**
   * Parses a NUL-delimited composite cursor string, returning {@code null} when blank.
   *
   * @param cursor raw decoded cursor string, or {@code null}
   * @param resource resource label used in validation errors
   * @return parsed {@link CompositeCursor}, or {@code null}
   */
  public static CompositeCursor parse(String cursor, String resource) {
    if (cursor == null || cursor.isBlank()) return null;
    int separator = cursor.lastIndexOf('\0');
    if (separator <= 0 || separator == cursor.length() - 1) {
      throw new IllegalArgumentException("invalid " + resource + " cursor");
    }
    return new CompositeCursor(cursor.substring(0, separator), cursor.substring(separator + 1));
  }

  /**
   * Joins {@code address} and {@code secondary} into a NUL-delimited cursor key.
   *
   * @param address canonical address component
   * @param secondary secondary tie-breaker component
   * @return encoded composite cursor key
   */
  public static String key(String address, String secondary) {
    return address + '\0' + secondary;
  }
}
