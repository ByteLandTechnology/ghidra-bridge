package app.byteland.ghidra.service.program;

/**
 * Metadata describing a program address space.
 *
 * @param name address space name
 * @param kind address space classification
 * @param size pointer size in bits
 * @param minAddress minimum representable address in the space
 * @param maxAddress maximum representable address in the space
 * @param isDefault whether this is the program default address space
 */
public record AddressSpaceResource(
    String name, Kind kind, int size, String minAddress, String maxAddress, boolean isDefault) {
  /** Classification of Ghidra address spaces. */
  public enum Kind {
    /** Physical or virtual RAM space. */
    RAM,
    /** Non-loaded file or debug space. */
    NON_LOADED,
    /** Architectural register space. */
    REGISTER,
    /** Function stack space. */
    STACK,
    /** External symbol linkage space. */
    EXTERNAL,
    /** Immediate constant space. */
    CONSTANT,
    /** Decompiler or p-code temporary space. */
    UNIQUE,
    /** Other specialized address space. */
    OTHER
  }
}
