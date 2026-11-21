package app.byteland.ghidra.service.function;

/**
 * Represents a caller or callee edge connected to a function.
 *
 * @param entry canonical entry-point address of the related function
 * @param name related function name
 * @param callSite canonical address of the call instruction
 * @param direction edge direction relative to the queried function
 * @param namespace parent namespace of the related function, or {@code null}
 * @param demangledName demangled C++ signature, or {@code null}
 */
public record FunctionCallResource(
    String entry, String name, String callSite, Direction direction,
    String namespace, String demangledName) {
  /**
   * Direction of a function call relationship.
   */
  public enum Direction {
    /** Functions that call the queried target function. */
    CALLERS,
    /** Functions called by the queried target function. */
    CALLEES
  }
}
