package app.byteland.ghidra.service.listing;

/**
 * Instruction control-flow override classifications supported by Ghidra.
 */
public enum FlowOverrideValue {
  /** No flow override is applied. */
  NONE,
  /** Treats the instruction as an unconditional branch. */
  BRANCH,
  /** Treats the instruction as a subroutine call. */
  CALL,
  /** Treats the instruction as a call followed by a return. */
  CALL_RETURN,
  /** Treats the instruction as a subroutine return. */
  RETURN
}
