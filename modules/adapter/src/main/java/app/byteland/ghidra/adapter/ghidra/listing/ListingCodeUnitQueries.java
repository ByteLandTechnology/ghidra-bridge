package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;

final class ListingCodeUnitQueries {
  private final GhidraSession context;

  ListingCodeUnitQueries(GhidraSession context) {
    this.context = context;
  }

  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions options, int limit, String kind, String cursorRaw) {
    int normalizedLimit = Page.clampLimit(limit);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);

    BoundedAddressScan<CodeUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    CodeUnit codeUnit =
        cursor == null ? firstCodeUnit(range.start()) : nextCodeUnitAfter(cursor);
    while (codeUnit != null) {
      if (range.afterEnd(codeUnit.getAddress())) {
        break;
      }
      CodeUnitResource.Kind kindValue = ListingDescriptions.classify(codeUnit);
      CodeUnitResource match =
          matchesKind(kind, kindValue)
              ? ListingDescriptions.toCodeUnitItem(codeUnit, kindValue, context)
              : null;
      String address = AddressUtil.canonicalAddress(codeUnit.getAddress());
      scan.visit(address, address, match);
      if (scan.stopped()) break;
      codeUnit = nextCodeUnitAfter(codeUnit.getAddress());
    }

    return scan.finish();
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private static boolean matchesKind(String requestedKind, CodeUnitResource.Kind actualKind) {
    return requestedKind == null
        || "all".equalsIgnoreCase(requestedKind)
        || actualKind.name().equalsIgnoreCase(requestedKind);
  }

  private CodeUnit firstCodeUnit(Address start) {
    CodeUnit codeUnit = codeUnitAt(start);
    if (codeUnit != null) {
      return codeUnit;
    }
    return nextCodeUnitAfter(start);
  }

  private CodeUnit codeUnitAt(Address address) {
    Instruction instruction = context.script().getInstructionAt(address);
    if (instruction != null) {
      return instruction;
    }
    Data data = context.script().getDataAt(address);
    if (data != null) {
      return data;
    }
    return context.script().getUndefinedDataAt(address);
  }

  private CodeUnit nextCodeUnitAfter(Address address) {
    CodeUnit nearest = context.script().getInstructionAfter(address);
    nearest = nearest(nearest, context.script().getDataAfter(address));
    return nearest(nearest, context.script().getUndefinedDataAfter(address));
  }

  private static CodeUnit nearest(CodeUnit current, CodeUnit candidate) {
    if (candidate == null) {
      return current;
    }
    if (current == null) {
      return candidate;
    }
    return candidate.getAddress().compareTo(current.getAddress()) < 0 ? candidate : current;
  }
}
