package app.byteland.ghidra.service.function;

public record FunctionCallResource(
    String entry, String name, String callSite, Direction direction) {
  public enum Direction {
    CALLERS,
    CALLEES
  }
}
