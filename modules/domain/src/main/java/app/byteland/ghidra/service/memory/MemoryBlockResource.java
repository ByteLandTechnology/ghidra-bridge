package app.byteland.ghidra.service.memory;

/**
 * Metadata and permissions for a program memory block.
 *
 * @param name memory block name
 * @param start inclusive start address
 * @param end inclusive end address
 * @param length block size in bytes
 * @param read whether the block is readable
 * @param write whether the block is writable
 * @param execute whether the block is executable
 * @param initialized whether the block has initialized backing bytes
 * @param isVolatile whether the block is marked volatile
 * @param overlay whether the block resides in an overlay space
 * @param kind memory block backing classification
 * @param comment optional memory block comment
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
  /** Backing storage classification for a memory block. */
  public enum Kind {
    /** Standard byte-addressable block. */
    DEFAULT,
    /** Bit-mapped block backed by another region. */
    BIT_MAPPED,
    /** Byte-mapped block backed by another region. */
    BYTE_MAPPED,
    /** Other specialized memory block type. */
    OTHER
  }
}
