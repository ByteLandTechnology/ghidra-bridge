package app.byteland.ghidra.service.memory;

/**
 * Describes a Ghidra program memory block and its permission flags.
 *
 * @param name block name
 * @param start canonical start address
 * @param end canonical end address
 * @param length block byte length
 * @param read {@code true} if readable
 * @param write {@code true} if writable
 * @param execute {@code true} if executable
 * @param initialized {@code true} if backed by initialized bytes
 * @param isVolatile {@code true} if marked volatile
 * @param overlay {@code true} if defined in an overlay space
 * @param kind Ghidra memory block storage kind
 * @param comment optional block comment, or {@code null}
 */
public record MemoryBlockResource(
    String name,
    String start,
    String end,
    long length,
    boolean read,
    boolean write,
    boolean execute,
    boolean initialized,
    boolean isVolatile,
    boolean overlay,
    Kind kind,
    String comment) {
  /**
   * Storage kind classification for a memory block.
   */
  public enum Kind {
    /** Standard byte-addressed memory block. */
    DEFAULT,
    /** Bit-mapped memory block. */
    BIT_MAPPED,
    /** Byte-mapped memory block. */
    BYTE_MAPPED,
    /** Unclassified memory block kind. */
    OTHER
  }
}
