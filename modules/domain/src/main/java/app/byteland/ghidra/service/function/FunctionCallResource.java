package app.byteland.ghidra.service.function;

/**
 * Caller or callee edge in a function call graph query.
 *
 * @param entry canonical entry address of the related function
 * @param name related function name
 * @param callSite instruction address of the call reference
 * @param direction whether the edge describes callers or callees
 * @param namespace namespace path of the related function
 * @param demangledName optional demangled function name
 */
public record FunctionCallResource(
    String entry, String name, String callSite, Direction direction,
    String namespace, String demangledName) {
  /** Traversal direction for function call relationships. */
  public enum Direction {
    /** Functions that call the target function. */
    CALLERS,
    /** Functions called by the target function. */
    CALLEES
  }
}
