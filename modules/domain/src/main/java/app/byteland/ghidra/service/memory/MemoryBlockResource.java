package app.byteland.ghidra.service.memory;

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
  public enum Kind {
    DEFAULT,
    BIT_MAPPED,
    BYTE_MAPPED,
    OTHER
  }
}
