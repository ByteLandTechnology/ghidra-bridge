package app.byteland.ghidra.service.program;

/**
 * Describes an address space in the active Ghidra program.
 *
 * @param name address space name
 * @param kind address space classification
 * @param size pointer bit width in this space
 * @param minAddress canonical minimum address
 * @param maxAddress canonical maximum address
 * @param isDefault {@code true} if this space is the program default address space
 */
public record AddressSpaceResource(
    String name, Kind kind, int size, String minAddress, String maxAddress, boolean isDefault) {
  /**
   * Classification of a Ghidra address space.
   */
  public enum Kind {
    /** Loaded RAM or code address space. */
    RAM,
    /** Non-loaded metadata address space. */
    NON_LOADED,
    /** Processor register space. */
    REGISTER,
    /** Call-frame stack space. */
    STACK,
    /** External linkage space. */
    EXTERNAL,
    /** Constant immediate space. */
    CONSTANT,
    /** P-code temporary unique space. */
    UNIQUE,
    /** Unclassified address space kind. */
    OTHER
  }
}
