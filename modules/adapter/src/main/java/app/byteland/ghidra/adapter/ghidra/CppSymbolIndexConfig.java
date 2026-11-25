package app.byteland.ghidra.adapter.ghidra;

/** Memory and batch bounds for a session C++ symbol index. */
public record CppSymbolIndexConfig(int maxEntries, long maxBytes, int batchSize) {
  public static final int DEFAULT_MAX_ENTRIES = 131_072;
  public static final long DEFAULT_MAX_BYTES = 64L * 1024L * 1024L;
  public static final int DEFAULT_BATCH_SIZE = 128;
  public static final String MAX_ENTRIES_PROPERTY = "ghidra.bridge.cppSymbolIndex.maxEntries";
  public static final String ALT_MAX_ENTRIES_PROPERTY = "ghidra.bridge.cppIndex.maxEntries";
  public static final String MAX_BYTES_PROPERTY = "ghidra.bridge.cppSymbolIndex.maxBytes";
  public static final String ALT_MAX_BYTES_PROPERTY = "ghidra.bridge.cppIndex.maxBytes";

  public CppSymbolIndexConfig {
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    if (maxBytes < 256L) {
      throw new IllegalArgumentException("maxBytes must be >= 256");
    }
    if (batchSize < 1) {
      throw new IllegalArgumentException("batchSize must be >= 1");
    }
  }

  public static CppSymbolIndexConfig defaults() {
    int configuredEntries =
        readPositiveInt(
            MAX_ENTRIES_PROPERTY,
            readPositiveInt(ALT_MAX_ENTRIES_PROPERTY, DEFAULT_MAX_ENTRIES));
    long configuredBytes =
        readPositiveLong(
            MAX_BYTES_PROPERTY,
            readPositiveLong(ALT_MAX_BYTES_PROPERTY, DEFAULT_MAX_BYTES));
    return new CppSymbolIndexConfig(
        configuredEntries, Math.max(256L, configuredBytes), DEFAULT_BATCH_SIZE);
  }

  private static int readPositiveInt(String property, int fallback) {
    String raw = System.getProperty(property);
    if (raw == null || raw.isBlank()) {
      return fallback;
    }
    try {
      int parsed = Integer.parseInt(raw.trim());
      return parsed >= 1 ? parsed : fallback;
    } catch (NumberFormatException ignored) {
      return fallback;
    }
  }

  private static long readPositiveLong(String property, long fallback) {
    String raw = System.getProperty(property);
    if (raw == null || raw.isBlank()) {
      return fallback;
    }
    try {
      long parsed = Long.parseLong(raw.trim());
      return parsed >= 1L ? parsed : fallback;
    } catch (NumberFormatException ignored) {
      return fallback;
    }
  }
}
