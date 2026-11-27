package app.byteland.ghidra.service.listing;

/**
 * Ghidra instruction control-flow override values.
 */
public enum FlowOverrideValue {
  /** No flow override; instruction uses its default control flow. */
  NONE,
  /** Treats the instruction as an unconditional or conditional branch. */
  BRANCH,
  /** Treats the instruction as a subroutine call. */
  CALL,
  /** Treats the instruction as a subroutine call followed by a return. */
  CALL_RETURN,
  /** Treats the instruction as a function return. */
  RETURN
}
