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
      AddressScanOptions options, int limit, String kind, String direction, String cursorRaw) {
    int normalizedLimit = Page.clampLimit(limit);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);
    boolean forward = !"backward".equalsIgnoreCase(direction);

    BoundedAddressScan<CodeUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    Address first = cursor == null ? range.start() : cursor;
    CodeUnit codeUnit =
        cursor == null ? firstCodeUnit(first, forward) : nextCodeUnitFrom(first, forward);
    while (codeUnit != null) {
      if (forward
          ? range.afterEnd(codeUnit.getAddress())
          : !range.includes(codeUnit.getAddress())) {
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
      codeUnit = nextCodeUnit(codeUnit, forward);
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

  private CodeUnit firstCodeUnit(Address start, boolean forward) {
    CodeUnit codeUnit = codeUnitAt(start);
    if (codeUnit != null) {
      return codeUnit;
    }
    return forward ? nextCodeUnitAfter(start) : nextCodeUnitBefore(start);
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

  private CodeUnit nextCodeUnit(CodeUnit codeUnit, boolean forward) {
    return forward
        ? nextCodeUnitAfter(codeUnit.getAddress())
        : nextCodeUnitBefore(codeUnit.getAddress());
  }

  private CodeUnit nextCodeUnitFrom(Address address, boolean forward) {
    return forward ? nextCodeUnitAfter(address) : nextCodeUnitBefore(address);
  }

  private CodeUnit nextCodeUnitAfter(Address address) {
    CodeUnit nearest = context.script().getInstructionAfter(address);
    nearest = nearest(nearest, context.script().getDataAfter(address), true);
    return nearest(nearest, context.script().getUndefinedDataAfter(address), true);
  }

  private CodeUnit nextCodeUnitBefore(Address address) {
    CodeUnit nearest = context.script().getInstructionBefore(address);
    nearest = nearest(nearest, context.script().getDataBefore(address), false);
    return nearest(nearest, context.script().getUndefinedDataBefore(address), false);
  }

  private static CodeUnit nearest(CodeUnit current, CodeUnit candidate, boolean forward) {
    if (candidate == null) {
      return current;
    }
    if (current == null) {
      return candidate;
    }
    int comparison = candidate.getAddress().compareTo(current.getAddress());
    if (comparison == 0) {
      return current;
    }
    return forward == comparison < 0 ? candidate : current;
  }
}
