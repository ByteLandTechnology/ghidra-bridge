package app.byteland.ghidra.service.listing;

public sealed interface FlowOverrideScope
    permits FlowOverrideScope.AddressScope,
        FlowOverrideScope.FunctionScope,
        FlowOverrideScope.RangeScope {
  String kind();

  record AddressScope(String address) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "address";
    }
  }

  record FunctionScope(String entry) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "function";
    }
  }

  record RangeScope(String start, String end) implements FlowOverrideScope {
    @Override
    public String kind() {
      return "range";
    }
  }
}
