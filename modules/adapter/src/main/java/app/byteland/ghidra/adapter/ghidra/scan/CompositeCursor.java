package app.byteland.ghidra.adapter.ghidra.scan;

/**
 * Two-part pagination cursor key composed of a canonical address and a secondary key.
 *
 * @param address canonical address component
 * @param secondary secondary tie-breaker key
 */
public record CompositeCursor(String address, String secondary) {
  /**
   * Parses a null-byte-delimited composite cursor key.
   *
   * @param cursor raw decoded cursor key, or {@code null}
   * @param resource resource label used in validation errors
   * @return parsed composite cursor, or {@code null} when blank
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
   * Joins an address and secondary key with a {@code '\0'} delimiter.
   *
   * @param address canonical address component
   * @param secondary secondary tie-breaker key
   * @return encoded composite cursor key
   */
  public static String key(String address, String secondary) {
    return address + '\0' + secondary;
  }
}
