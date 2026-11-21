package app.byteland.ghidra.service.program;

/**
 * Describes the processor language, compiler spec, byte order, and pointer width of a program.
 *
 * @param languageId Ghidra language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param processor processor family name
 * @param endian byte order of the target architecture
 * @param addressSize default pointer width in bits
 */
public record ProgramLanguageResource(
    String languageId, String compilerSpecId, String processor, Endian endian, int addressSize) {
  /**
   * Target architecture byte order.
   */
  public enum Endian {
    /** Most significant byte stored at the lowest address. */
    BIG,
    /** Least significant byte stored at the lowest address. */
    LITTLE
  }
}
