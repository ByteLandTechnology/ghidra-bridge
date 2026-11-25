package app.byteland.ghidra.service.listing;

/**
 * Target address, function, or range scope for instruction flow override queries and mutations.
 */
public sealed interface FlowOverrideScope
    permits FlowOverrideScope.AddressScope,
        FlowOverrideScope.FunctionScope,
        FlowOverrideScope.RangeScope {
  /**
   * Returns the scope kind identifier.
   *
   * @return {@code "address"}, {@code "function"}, or {@code "range"}
   */
  String kind();

  /**
   * Single instruction address scope.
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
   * Function body scope identified by entry address.
   *
   * @param entry target function entry address
   */
  record FunctionScope(String entry) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "function";
    }
  }

  /**
   * Inclusive address range scope.
   *
   * @param start inclusive start address
   * @param end inclusive end address
   */
  record RangeScope(String start, String end) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "range";
    }
  }
}
