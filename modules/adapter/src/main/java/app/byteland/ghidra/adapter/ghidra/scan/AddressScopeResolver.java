package app.byteland.ghidra.adapter.ghidra.scan;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import java.util.NoSuchElementException;

public final class AddressScopeResolver {
  private final GhidraSession context;

  public AddressScopeResolver(GhidraSession context) {
    this.context = context;
  }

  public AddressSetView resolve(FlowOverrideScope scope) {
    return switch (scope) {
      case FlowOverrideScope.FunctionScope function -> resolveFunction(function.entry());
      case FlowOverrideScope.RangeScope range -> resolveRange(range.start(), range.end());
      case FlowOverrideScope.AddressScope address -> resolveAddress(address.address());
    };
  }

  private AddressSetView resolveAddress(String addressRaw) {
    Address address = context.parseAddress(addressRaw);
    return new AddressSet(address, address);
  }

  private AddressSetView resolveFunction(String entryRaw) {
    Address entry = context.parseAddress(entryRaw);
    Function function = context.currentProgram().getListing().getFunctionAt(entry);
    if (function == null) {
      throw new NoSuchElementException("no function at entry address");
    }
    return function.getBody();
  }

  private AddressSetView resolveRange(String startRaw, String endRaw) {
    Address start = context.parseAddress(startRaw);
    Address end =
        endRaw == null ? start.getAddressSpace().getMaxAddress() : context.parseAddress(endRaw);
    if (!start.getAddressSpace().equals(end.getAddressSpace())) {
      throw new IllegalArgumentException("start and end must be in the same address space");
    }
    if (start.compareTo(end) > 0) {
      throw new IllegalArgumentException("start must not be greater than end");
    }
    return new AddressSet(start, end);
  }
}
