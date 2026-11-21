package app.byteland.ghidra.service.program;

/**
 * Describes processor architecture, compiler specification, endianness, and pointer width.
 *
 * @param languageId Ghidra language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param processor processor family name
 * @param endian byte order
 * @param addressSize default pointer width in bits
 */
public record ProgramLanguageResource(
    String languageId, String compilerSpecId, String processor, Endian endian, int addressSize) {
  /** Processor byte order. */
  public enum Endian {
    /** Most significant byte first. */
    BIG,
    /** Least significant byte first. */
    LITTLE
  }
}
