package app.byteland.ghidra.adapter.ghidra.scan;

/**
 * Two-part pagination cursor combining a canonical address and a secondary sort key.
 *
 * @param address canonical {@code space:offset} cursor component
 * @param secondary secondary tie-breaker key within {@code address}
 */
public record CompositeCursor(String address, String secondary) {
  /**
   * Parses a NUL-delimited composite cursor string, or returns {@code null} when blank.
   *
   * @param cursor raw decoded cursor payload, or {@code null}
   * @param resource resource label included in validation failure messages
   * @return parsed {@link CompositeCursor}, or {@code null} when {@code cursor} is blank
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
   * Formats {@code address} and {@code secondary} into a NUL-delimited composite cursor key.
   *
   * @param address canonical {@code space:offset} cursor component
   * @param secondary secondary tie-breaker key
   * @return NUL-delimited composite cursor string
   */
  public static String key(String address, String secondary) {
    return address + '\0' + secondary;
  }
}
