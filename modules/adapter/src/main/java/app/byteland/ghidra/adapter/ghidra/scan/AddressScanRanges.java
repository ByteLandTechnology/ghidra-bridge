package app.byteland.ghidra.adapter.ghidra.scan;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

/**
 * Resolves and validates bounded start/end address ranges for program scans.
 */
public final class AddressScanRanges {
  private AddressScanRanges() {}

  /**
   * Resolves scan bounds from {@code options} against the active program's address spaces.
   *
   * @param context active Ghidra session
   * @param options requested scan start and end options
   * @param defaultEndToAddressSpace {@code true} to default an omitted end address to the program or space end
   * @return validated {@link Resolved} address range
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
   * Validates that {@code start} and optional {@code end} form an ordered single-space range.
   *
   * @param start inclusive start address
   * @param end optional inclusive end address, or {@code null}
   * @return validated {@link Resolved} address range
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
   * Validated address range within a single Ghidra {@link AddressSpace}.
   *
   * @param start inclusive start address
   * @param end optional inclusive end address, or {@code null}
   */
  public record Resolved(Address start, Address end) {
    /**
     * Returns the canonical {@code space:offset} string for {@link #start()}.
     *
     * @return canonical start address string
     */
    public String startText() {
      return AddressUtil.canonicalAddress(start);
    }

    /**
     * Returns the canonical {@code space:offset} string for {@link #end()}, or {@code null}.
     *
     * @return canonical end address string, or {@code null} when unbounded
     */
    public String endText() {
      return end == null ? null : AddressUtil.canonicalAddress(end);
    }

    /**
     * Returns {@code true} when {@code address} lies within {@code start..end}.
     *
     * @param address candidate address in the same space
     * @return {@code true} if {@code address} is inside the range
     */
    public boolean includes(Address address) {
      return address.compareTo(start) >= 0 && (end == null || address.compareTo(end) <= 0);
    }

    /**
     * Returns {@code true} when {@link #end()} is set and {@code address} exceeds it.
     *
     * @param address candidate address in the same space
     * @return {@code true} if {@code address} is past {@link #end()}
     */
    public boolean afterEnd(Address address) {
      return end != null && address.compareTo(end) > 0;
    }
  }
}
