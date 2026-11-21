package app.byteland.ghidra.service.listing;

/**
 * Target scope for reading or modifying instruction flow overrides.
 */
public sealed interface FlowOverrideScope
    permits FlowOverrideScope.AddressScope,
        FlowOverrideScope.FunctionScope,
        FlowOverrideScope.RangeScope {
  /**
   * Returns the wire discriminator kind for this scope.
   *
   * @return scope kind identifier
   */
  String kind();

  /**
   * Targets a single instruction address.
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
   * Targets all instructions in a function body.
   *
   * @param entry function entry point address
   */
  record FunctionScope(String entry) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "function";
    }
  }

  /**
   * Targets all instructions within an inclusive address range.
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
