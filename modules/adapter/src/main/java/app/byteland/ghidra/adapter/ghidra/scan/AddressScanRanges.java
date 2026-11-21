package app.byteland.ghidra.adapter.ghidra.scan;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * Resolves and validates inclusive address scan ranges within a Ghidra program.
 */
public final class AddressScanRanges {
  private AddressScanRanges() {}

  /**
   * Resolves start and optional end addresses from {@link AddressScanOptions}.
   *
   * @param context active Ghidra session
   * @param options scan range options
   * @param defaultEndToAddressSpace {@code true} to default an omitted end address to the space end
   * @return resolved inclusive address range
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
   * Validates and constructs a {@link Resolved} range from start and optional end addresses.
   *
   * @param start inclusive start address
   * @param end optional inclusive end address in the same address space
   * @return validated address range
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
   * Validated inclusive Ghidra address scan range.
   *
   * @param start inclusive start address
   * @param end optional inclusive end address
   */
  public record Resolved(Address start, Address end) {
    /**
     * Returns the canonical string form of {@link #start()}.
     *
     * @return canonical start address
     */
    public String startText() {
      return AddressUtil.canonicalAddress(start);
    }

    /**
     * Returns the canonical string form of {@link #end()}, or {@code null} when unbounded.
     *
     * @return canonical end address, or {@code null}
     */
    public String endText() {
      return end == null ? null : AddressUtil.canonicalAddress(end);
    }

    /**
     * Checks whether {@code address} falls within this inclusive range.
     *
     * @param address candidate Ghidra address
     * @return {@code true} when {@code address} is inside the range
     */
    public boolean includes(Address address) {
      return address.compareTo(start) >= 0 && (end == null || address.compareTo(end) <= 0);
    }

    /**
     * Checks whether {@code address} is strictly past {@link #end()}.
     *
     * @param address candidate Ghidra address
     * @return {@code true} when an end bound exists and {@code address} exceeds it
     */
    public boolean afterEnd(Address address) {
      return end != null && address.compareTo(end) > 0;
    }
  }
}
