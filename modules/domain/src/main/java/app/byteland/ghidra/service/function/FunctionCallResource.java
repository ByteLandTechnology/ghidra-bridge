package app.byteland.ghidra.service.function;

/**
 * Describes a caller or callee edge in the function call graph.
 *
 * @param entry peer function entry point address
 * @param name peer function name
 * @param callSite instruction address where the call occurs
 * @param direction call relationship direction
 * @param namespace peer function namespace
 * @param demangledName optional demangled C++ peer name
 */
public record FunctionCallResource(
    String entry, String name, String callSite, Direction direction,
    String namespace, String demangledName) {
  /** Relationship direction relative to the queried function. */
  public enum Direction {
    /** Functions that call the queried function. */
    CALLERS,
    /** Functions called by the queried function. */
    CALLEES
  }
}
