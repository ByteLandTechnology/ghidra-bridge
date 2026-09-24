package app.byteland.ghidra.adapter.ghidra.scan;

public record CompositeCursor(String address, String secondary) {
  public static CompositeCursor parse(String cursor, String resource) {
    if (cursor == null || cursor.isBlank()) return null;
    int separator = cursor.lastIndexOf('\0');
    if (separator <= 0 || separator == cursor.length() - 1) {
      throw new IllegalArgumentException("invalid " + resource + " cursor");
    }
    return new CompositeCursor(cursor.substring(0, separator), cursor.substring(separator + 1));
  }

  public static String key(String address, String secondary) {
    return address + '\0' + secondary;
  }
}
