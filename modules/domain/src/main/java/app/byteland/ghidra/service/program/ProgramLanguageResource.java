package app.byteland.ghidra.service.program;

/**
 * Processor architecture and compiler specification metadata for the active program.
 *
 * @param languageId Ghidra processor language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param processor processor family name
 * @param endian byte order of the language
 * @param addressSize default address width in bits
 */
public record ProgramLanguageResource(
    String languageId, String compilerSpecId, String processor, Endian endian, int addressSize) {
  /** Byte order of a processor language. */
  public enum Endian {
    /** Most-significant byte first. */
    BIG,
    /** Least-significant byte first. */
    LITTLE
  }
}
