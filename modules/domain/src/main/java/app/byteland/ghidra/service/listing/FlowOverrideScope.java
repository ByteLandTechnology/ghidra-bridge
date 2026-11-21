package app.byteland.ghidra.service.listing;

/**
 * Target address scope for instruction flow override queries and updates.
 */
public sealed interface FlowOverrideScope
    permits FlowOverrideScope.AddressScope,
        FlowOverrideScope.FunctionScope,
        FlowOverrideScope.RangeScope {
  /**
   * Returns the wire discriminator string for this scope variant.
   *
   * @return {@code "address"}, {@code "function"}, or {@code "range"}
   */
  String kind();

  /**
   * Scope for a single instruction address.
   *
   * @param address target instruction address
   */
  record AddressScope(String address) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "address";
    }
  }

  /**
   * Scope for all instructions in a function body.
   *
   * @param entry function entry-point address
   */
  record FunctionScope(String entry) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "function";
    }
  }

  /**
   * Scope for an inclusive address range.
   *
   * @param start inclusive range start address
   * @param end inclusive range end address
   */
  record RangeScope(String start, String end) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "range";
    }
  }
}
