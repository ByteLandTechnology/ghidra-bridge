package app.byteland.ghidra.service.listing;

/**
 * Control-flow override values supported on disassembled instructions.
 */
public enum FlowOverrideValue {
  /** Default instruction control flow with no override. */
  NONE,
  /** Treats flow as an unconditional or conditional branch. */
  BRANCH,
  /** Treats flow as a subroutine call. */
  CALL,
  /** Treats flow as a subroutine call that terminates with a return. */
  CALL_RETURN,
  /** Treats flow as a subroutine return. */
  RETURN
}
