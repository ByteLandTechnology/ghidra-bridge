package app.byteland.ghidra.service.memory;

/**
 * Metadata describing a contiguous program memory block.
 *
 * @param name memory block name
 * @param start inclusive block start address
 * @param end inclusive block end address
 * @param length block size in bytes
 * @param read whether the block is readable
 * @param write whether the block is writable
 * @param execute whether the block is executable
 * @param initialized whether the block has initialized backing bytes
 * @param isVolatile whether the block is marked volatile
 * @param overlay whether the block resides in an overlay space
 * @param kind storage backing kind of the memory block
 * @param comment optional block comment
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
  /** Backing representation kind of a program memory block. */
  public enum Kind {
    /** Standard RAM or file-backed memory block. */
    DEFAULT,
    /** Bit-mapped memory block. */
    BIT_MAPPED,
    /** Byte-mapped memory block. */
    BYTE_MAPPED,
    /** Other specialized memory block type. */
    OTHER
  }
}
