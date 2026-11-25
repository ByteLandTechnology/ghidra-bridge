package app.byteland.ghidra.service.function;

/**
 * Represents a caller or callee relationship for a function.
 *
 * @param entry entry point address of the related function
 * @param name name of the related function
 * @param callSite instruction address of the call site
 * @param direction call relationship direction
 * @param namespace namespace of the related function
 * @param demangledName demangled name of the related function, if available
 */
public record FunctionCallResource(
    String entry, String name, String callSite, Direction direction,
    String namespace, String demangledName) {
  /** Direction of a function call edge relative to a queried function. */
  public enum Direction {
    /** Functions that call the queried function. */
    CALLERS,
    /** Functions called by the queried function. */
    CALLEES
  }
}
