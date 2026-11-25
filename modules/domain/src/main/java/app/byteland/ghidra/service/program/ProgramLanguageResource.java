package app.byteland.ghidra.service.program;

/**
 * Processor language and compiler specification metadata for a program.
 *
 * @param languageId Ghidra language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param processor processor family name
 * @param endian byte order of the target architecture
 * @param addressSize default pointer size in bits
 */
public record ProgramLanguageResource(
    String languageId, String compilerSpecId, String processor, Endian endian, int addressSize) {
  /** Architectural byte order. */
  public enum Endian {
    /** Most-significant byte first. */
    BIG,
    /** Least-significant byte first. */
    LITTLE
  }
}
