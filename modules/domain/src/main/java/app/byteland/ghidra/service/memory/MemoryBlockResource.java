package app.byteland.ghidra.service.memory;

/**
 * Describes a program memory block, permissions, and storage type.
 *
 * @param name memory block name
 * @param start inclusive start address
 * @param end inclusive end address
 * @param length block size in bytes
 * @param read true when readable
 * @param write true when writable
 * @param execute true when executable
 * @param initialized true when backed by initialized bytes
 * @param isVolatile true when marked volatile
 * @param overlay true when defined in an overlay space
 * @param kind memory block backing classification
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
  /** Memory block backing storage categories. */
  public enum Kind {
    /** Standard flat byte-addressed memory block. */
    DEFAULT,
    /** Bit-mapped memory block. */
    BIT_MAPPED,
    /** Byte-mapped memory block. */
    BYTE_MAPPED,
    /** Other specialized memory block type. */
    OTHER
  }
}
