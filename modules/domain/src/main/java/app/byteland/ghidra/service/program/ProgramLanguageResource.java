package app.byteland.ghidra.service.program;

public record ProgramLanguageResource(
    String languageId, String compilerSpecId, String processor, Endian endian, int addressSize) {
  public enum Endian {
    BIG,
    LITTLE
  }
}
