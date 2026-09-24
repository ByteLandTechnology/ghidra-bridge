package app.byteland.ghidra.adapter.ghidra.scan;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public final class AddressScanRanges {
  private AddressScanRanges() {}

  public static Resolved resolve(
      GhidraSession context, AddressScanOptions options, boolean defaultEndToAddressSpace) {
    Address start =
        options.start() == null
            ? context.currentProgram().getMinAddress()
            : context.parseAddress(options.start());
    if (start == null) {
      AddressSpace space = context.script().getAddressFactory().getDefaultAddressSpace();
      if (space == null) throw new IllegalStateException("no default address space");
      start = space.getMinAddress();
    }
    Address end =
        options.end() == null
            ? (defaultEndToAddressSpace ? defaultProgramEnd(context, start) : null)
            : context.parseAddress(options.end());
    return of(start, end);
  }

  private static Address defaultProgramEnd(GhidraSession context, Address start) {
    Address programEnd = context.currentProgram().getMaxAddress();
    if (programEnd != null
        && start.getAddressSpace().equals(programEnd.getAddressSpace())
        && programEnd.compareTo(start) >= 0) {
      return programEnd;
    }
    return start.getAddressSpace().getMaxAddress();
  }

  public static Resolved of(Address start, Address end) {
    if (start == null) throw new IllegalArgumentException("start is required");
    if (end != null) {
      if (!start.getAddressSpace().equals(end.getAddressSpace())) {
        throw new IllegalArgumentException("start and end must be in the same address space");
      }
      if (start.compareTo(end) > 0) {
        throw new IllegalArgumentException("start must not be greater than end");
      }
    }
    return new Resolved(start, end);
  }

  public record Resolved(Address start, Address end) {
    public String startText() {
      return AddressUtil.canonicalAddress(start);
    }

    public String endText() {
      return end == null ? null : AddressUtil.canonicalAddress(end);
    }

    public boolean includes(Address address) {
      return address.compareTo(start) >= 0 && (end == null || address.compareTo(end) <= 0);
    }

    public boolean afterEnd(Address address) {
      return end != null && address.compareTo(end) > 0;
    }
  }
}
