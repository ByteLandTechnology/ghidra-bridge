package app.byteland.ghidra.service.program;

/**
 * Metadata for an address space in the active program.
 *
 * @param name address space name
 * @param kind address space classification
 * @param size pointer width in bits
 * @param minAddress minimum address in the space
 * @param maxAddress maximum address in the space
 * @param isDefault whether the space is the default program address space
 */
public record AddressSpaceResource(
    String name, Kind kind, int size, String minAddress, String maxAddress, boolean isDefault) {
  /** Classification of Ghidra address spaces. */
  public enum Kind {
    /** Loaded memory space such as RAM or CODE. */
    RAM,
    /** Non-loaded memory space. */
    NON_LOADED,
    /** Processor register space. */
    REGISTER,
    /** Call frame stack space. */
    STACK,
    /** External symbol linkage space. */
    EXTERNAL,
    /** Immediate constant space. */
    CONSTANT,
    /** P-code temporary unique space. */
    UNIQUE,
    /** Other specialized address space. */
    OTHER
  }
}
