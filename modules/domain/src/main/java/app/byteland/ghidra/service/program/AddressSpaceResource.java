package app.byteland.ghidra.service.program;

/**
 * Describes a program address space and its bounds.
 *
 * @param name address space name
 * @param kind address space classification
 * @param size pointer width in bits
 * @param minAddress minimum address in the space
 * @param maxAddress maximum address in the space
 * @param isDefault true when this space is the default program address space
 */
public record AddressSpaceResource(
    String name, Kind kind, int size, String minAddress, String maxAddress, boolean isDefault) {
  /** Classification of program address spaces. */
  public enum Kind {
    /** Loaded RAM or ROM memory space. */
    RAM,
    /** Unloaded memory space. */
    NON_LOADED,
    /** Processor register space. */
    REGISTER,
    /** Call stack space. */
    STACK,
    /** External symbol linkage space. */
    EXTERNAL,
    /** Constant value space. */
    CONSTANT,
    /** Decompiler temporary variable space. */
    UNIQUE,
    /** Address space outside standard categories. */
    OTHER
  }
}
