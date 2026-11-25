package app.byteland.ghidra.service.listing;

/** Control-flow override kind applied to an instruction. */
public enum FlowOverrideValue {
  /** No flow override is active. */
  NONE,
  /** Treats the primary flow as an unconditional or conditional jump. */
  BRANCH,
  /** Treats the primary flow as a function call. */
  CALL,
  /** Treats the primary flow as a call followed by a return. */
  CALL_RETURN,
  /** Treats the instruction as returning from the current function. */
  RETURN
}
