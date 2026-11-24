package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.listing.AddressOrRangeScope;
import app.byteland.ghidra.service.listing.CodeUnitClearReceipt;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

final class ListingCodeUnitMutations {
  private final GhidraSession context;

  ListingCodeUnitMutations(GhidraSession context) {
    this.context = context;
  }

  CodeUnitClearReceipt clearCodeUnits(AddressOrRangeScope scope, boolean clearContext) {
    Address start;
    Address end;
    switch (scope) {
      case AddressOrRangeScope.AddressScope address -> {
        start = context.parseAddress(address.address());
        end = start;
      }
      case AddressOrRangeScope.RangeScope range -> {
        start = context.parseAddress(range.start());
        end = context.parseAddress(range.end());
        validateRange(start, end);
      }
    }

    Listing listing = context.currentProgram().getListing();
    Address clearStart = expandClearStart(listing, start);
    Address clearEnd = expandClearEnd(listing, end);
    listing.clearCodeUnits(clearStart, clearEnd, clearContext);
    return new CodeUnitClearReceipt(
        AddressUtil.canonicalAddress(clearStart), AddressUtil.canonicalAddress(clearEnd), true);
  }

  static void validateRange(Address start, Address end) {
    if (!start.getAddressSpace().equals(end.getAddressSpace())) {
      throw new IllegalArgumentException("start and end must be in the same address space");
    }
    if (start.compareTo(end) > 0) {
      throw new IllegalArgumentException("start must not be greater than end");
    }
  }

  static Address expandClearStart(Listing listing, Address start) {
    CodeUnit first = listing.getCodeUnitContaining(start);
    if (isDefinedCodeUnit(first) && first.getMinAddress().compareTo(start) < 0) {
      return first.getMinAddress();
    }
    return start;
  }

  static Address expandClearEnd(Listing listing, Address end) {
    CodeUnit last = listing.getCodeUnitContaining(end);
    if (isDefinedCodeUnit(last) && last.getMaxAddress().compareTo(end) > 0) {
      return last.getMaxAddress();
    }
    return end;
  }

  static boolean isDefinedCodeUnit(CodeUnit codeUnit) {
    if (codeUnit instanceof Instruction) {
      return true;
    }
    return codeUnit instanceof Data data && data.isDefined();
  }
}
