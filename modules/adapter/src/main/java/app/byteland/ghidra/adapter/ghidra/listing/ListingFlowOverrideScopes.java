package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import java.util.NoSuchElementException;

final class ListingFlowOverrideScopes {
  record ResolvedScope(AddressSetView addresses) {}

  private final GhidraSession context;

  ListingFlowOverrideScopes(GhidraSession context) {
    this.context = context;
  }

  ResolvedScope resolve(FlowOverrideScope scope, String selectorTarget) {
    return switch (scope) {
      case FlowOverrideScope.FunctionScope function ->
          resolveFunction(function.entry(), selectorTarget + "/entry");
      case FlowOverrideScope.RangeScope range ->
          resolveRange(range.start(), range.end(), selectorTarget);
      case FlowOverrideScope.AddressScope address ->
          resolveAddress(address.address(), selectorTarget + "/address");
    };
  }

  private ResolvedScope resolveAddress(String addressRaw, String target) {
    Address address = context.parseAddress(addressRaw, target);
    return new ResolvedScope(new AddressSet(address, address));
  }

  private ResolvedScope resolveFunction(String entryRaw, String target) {
    Address entry = context.parseAddress(entryRaw, target);
    Function function = context.script().getFunctionAt(entry);
    if (function == null) {
      throw new NoSuchElementException("no function at entry address");
    }
    return new ResolvedScope(function.getBody());
  }

  private ResolvedScope resolveRange(String startRaw, String endRaw, String selectorTarget) {
    Address start = context.parseAddress(startRaw, selectorTarget + "/start");
    Address end =
        endRaw == null
            ? start.getAddressSpace().getMaxAddress()
            : context.parseAddress(endRaw, selectorTarget + "/end");
    if (!start.getAddressSpace().equals(end.getAddressSpace())) {
      throw new IllegalArgumentException("start and end must be in the same address space");
    }
    if (start.compareTo(end) > 0) {
      throw new IllegalArgumentException("start must not be greater than end");
    }
    return new ResolvedScope(new AddressSet(start, end));
  }
}
