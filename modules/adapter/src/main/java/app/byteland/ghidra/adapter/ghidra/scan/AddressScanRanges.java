package app.byteland.ghidra.adapter.ghidra.scan;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/** Resolves and validates start/end address bounds for bounded program scans. */
public final class AddressScanRanges {
  private AddressScanRanges() {}

  /**
   * Resolves scan start and optional end addresses against the active Ghidra program.
   *
   * @param context active Ghidra session
   * @param options caller-provided scan options
   * @param defaultEndToAddressSpace {@code true} to default an omitted end address to the program
   *     or address-space maximum
   * @return validated resolved address bounds
   */
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

  /**
   * Validates that {@code start} and optional {@code end} form an ordered same-space range.
   *
   * @param start inclusive start address
   * @param end optional inclusive end address
   * @return resolved address range
   */
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

  /**
   * Validated start and optional end address pair in a single address space.
   *
   * @param start inclusive start address
   * @param end inclusive end address, or {@code null} when open-ended
   */
  public record Resolved(Address start, Address end) {
    /**
     * Returns the canonical string form of {@link #start()}.
     *
     * @return canonical start address text
     */
    public String startText() {
      return AddressUtil.canonicalAddress(start);
    }

    /**
     * Returns the canonical string form of {@link #end()}, or {@code null} when open-ended.
     *
     * @return canonical end address text, or {@code null}
     */
    public String endText() {
      return end == null ? null : AddressUtil.canonicalAddress(end);
    }

    /**
     * Returns whether {@code address} falls within {@code [start, end]}.
     *
     * @param address candidate address in the same space
     * @return {@code true} if {@code address} is inside the range
     */
    public boolean includes(Address address) {
      return address.compareTo(start) >= 0 && (end == null || address.compareTo(end) <= 0);
    }

    /**
     * Returns whether {@code address} lies strictly past {@link #end()}.
     *
     * @param address candidate address in the same space
     * @return {@code true} if an end bound exists and {@code address > end}
     */
    public boolean afterEnd(Address address) {
      return end != null && address.compareTo(end) > 0;
    }
  }
}
