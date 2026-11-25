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
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Listing;
import java.util.Iterator;

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
    Listing listing = context.currentProgram().getListing();

    if ("instruction".equalsIgnoreCase(kind)) {
      return listFiltered(listing, range, cursor, scan, CodeUnitResource.Kind.INSTRUCTION, true);
    }
    if ("data".equalsIgnoreCase(kind)) {
      return listFiltered(listing, range, cursor, scan, CodeUnitResource.Kind.DATA, false);
    }

    Address iterationStart = ListingInstructionQueries.iterationStart(range, cursor);
    if (range.afterEnd(iterationStart)) {
      return scan.finish();
    }
    CodeUnitIterator codeUnits = listing.getCodeUnits(iterationStart, true);
    while (codeUnits.hasNext()) {
      CodeUnit codeUnit = codeUnits.next();
      Address address = codeUnit.getAddress();
      if (ListingInstructionQueries.atOrBeforeCursor(address, cursor)) continue;
      if (range.afterEnd(address)) break;
      CodeUnitResource.Kind kindValue = ListingDescriptions.classify(codeUnit);
      CodeUnitResource match =
          matchesKind(kind, kindValue)
              ? ListingDescriptions.toCodeUnitItem(codeUnit, kindValue, context)
              : null;
      String canonical = AddressUtil.canonicalAddress(address);
      scan.visit(canonical, canonical, match);
      if (scan.stopped()) break;
    }

    return scan.finish();
  }

  private Page<CodeUnitResource> listFiltered(
      Listing listing,
      AddressScanRanges.Resolved range,
      Address cursor,
      BoundedAddressScan<CodeUnitResource> scan,
      CodeUnitResource.Kind targetKind,
      boolean instructionsOnly) {
    CodeUnit firstCodeUnit = firstCodeUnitInWindow(listing, range, cursor);
    if (firstCodeUnit == null) {
      return scan.finish();
    }
    scan.anchorStart(AddressUtil.canonicalAddress(firstCodeUnit.getAddress()));

    Address iterationStart = ListingInstructionQueries.iterationStart(range, cursor);
    Iterator<? extends CodeUnit> codeUnits =
        instructionsOnly
            ? listing.getInstructions(iterationStart, true)
            : listing.getDefinedData(iterationStart, true);
    CodeUnit lastVisited = null;
    while (codeUnits.hasNext()) {
      CodeUnit codeUnit = codeUnits.next();
      Address address = codeUnit.getAddress();
      if (ListingInstructionQueries.atOrBeforeCursor(address, cursor)) continue;
      if (range.afterEnd(address)) break;
      String canonical = AddressUtil.canonicalAddress(address);
      scan.visit(
          canonical, canonical, ListingDescriptions.toCodeUnitItem(codeUnit, targetKind, context));
      lastVisited = codeUnit;
      if (scan.stopped()) break;
    }

    if (!scan.stopped()) {
      CodeUnit boundaryCandidate = lastVisited != null ? lastVisited : firstCodeUnit;
      if (reachesWindowEnd(boundaryCandidate, range)) {
        scan.anchorCompletedEnd(AddressUtil.canonicalAddress(boundaryCandidate.getAddress()));
      } else {
        CodeUnit lastCodeUnit = lastCodeUnitInWindow(listing, range);
        if (lastCodeUnit != null) {
          scan.anchorCompletedEnd(AddressUtil.canonicalAddress(lastCodeUnit.getAddress()));
        }
      }
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

  private static CodeUnit firstCodeUnitInWindow(
      Listing listing, AddressScanRanges.Resolved range, Address cursor) {
    if (cursor != null && cursor.compareTo(range.start()) >= 0) {
      if (range.end() != null && cursor.compareTo(range.end()) >= 0) {
        return null;
      }
      CodeUnit afterCursor = listing.getCodeUnitAfter(cursor);
      return afterCursor != null && !range.afterEnd(afterCursor.getAddress()) ? afterCursor : null;
    }
    CodeUnit atStart = listing.getCodeUnitAt(range.start());
    CodeUnit first = atStart != null ? atStart : listing.getCodeUnitAfter(range.start());
    return first != null && !range.afterEnd(first.getAddress()) ? first : null;
  }

  private static CodeUnit lastCodeUnitInWindow(Listing listing, AddressScanRanges.Resolved range) {
    if (range.end() == null) {
      return null;
    }
    CodeUnit containingEnd = listing.getCodeUnitContaining(range.end());
    CodeUnit last = containingEnd != null ? containingEnd : listing.getCodeUnitBefore(range.end());
    return last != null
            && last.getAddress().compareTo(range.start()) >= 0
            && !range.afterEnd(last.getAddress())
        ? last
        : null;
  }

  private static boolean reachesWindowEnd(CodeUnit codeUnit, AddressScanRanges.Resolved range) {
    if (range.end() == null) {
      return false;
    }
    Address maxAddress = codeUnit.getMaxAddress();
    return maxAddress != null && maxAddress.compareTo(range.end()) >= 0;
  }
}
