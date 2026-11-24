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
import java.util.Set;

final class ListingCodeUnitQueries {
  private final GhidraSession context;

  ListingCodeUnitQueries(GhidraSession context) {
    this.context = context;
  }

  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions options, int limit, String kind, String direction, String cursorRaw) {
    return listCodeUnits(options, limit, kind, direction, cursorRaw, null);
  }

  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions options,
      int limit,
      String kind,
      String direction,
      String cursorRaw,
      Set<String> fields) {
    int normalizedLimit = Page.clampLimit(limit);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);
    boolean forward = !"backward".equalsIgnoreCase(direction);

    BoundedAddressScan<CodeUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    Listing listing = context.currentProgram().getListing();

    if ("instruction".equalsIgnoreCase(kind)) {
      return listFiltered(
          listing, range, cursor, forward, scan, CodeUnitResource.Kind.INSTRUCTION, true, fields);
    }
    if ("data".equalsIgnoreCase(kind)) {
      return listFiltered(
          listing, range, cursor, forward, scan, CodeUnitResource.Kind.DATA, false, fields);
    }

    Address iterationStart = ListingInstructionQueries.iterationStart(range, cursor, forward);
    if (ListingInstructionQueries.outOfRange(iterationStart, range, forward)) {
      return scan.finish();
    }
    CodeUnitIterator codeUnits = listing.getCodeUnits(iterationStart, forward);
    while (codeUnits.hasNext()) {
      CodeUnit codeUnit = codeUnits.next();
      Address address = codeUnit.getAddress();
      if (ListingInstructionQueries.atOrBeforeCursor(address, cursor, forward)) continue;
      if (ListingInstructionQueries.outOfRange(address, range, forward)) break;
      CodeUnitResource.Kind kindValue = ListingDescriptions.classify(codeUnit);
      CodeUnitResource match =
          matchesKind(kind, kindValue)
              ? ListingDescriptions.toCodeUnitItem(codeUnit, kindValue, context, fields)
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
      boolean forward,
      BoundedAddressScan<CodeUnitResource> scan,
      CodeUnitResource.Kind targetKind,
      boolean instructionsOnly,
      Set<String> fields) {
    CodeUnit firstCodeUnit = firstCodeUnitInWindow(listing, range, cursor, forward);
    if (firstCodeUnit == null) {
      return scan.finish();
    }
    scan.anchorStart(AddressUtil.canonicalAddress(firstCodeUnit.getAddress()));

    Address iterationStart = ListingInstructionQueries.iterationStart(range, cursor, forward);
    Iterator<? extends CodeUnit> codeUnits =
        instructionsOnly
            ? listing.getInstructions(iterationStart, forward)
            : listing.getDefinedData(iterationStart, forward);
    CodeUnit lastVisited = null;
    while (codeUnits.hasNext()) {
      CodeUnit codeUnit = codeUnits.next();
      Address address = codeUnit.getAddress();
      if (ListingInstructionQueries.atOrBeforeCursor(address, cursor, forward)) continue;
      if (ListingInstructionQueries.outOfRange(address, range, forward)) break;
      String canonical = AddressUtil.canonicalAddress(address);
      scan.visit(
          canonical,
          canonical,
          ListingDescriptions.toCodeUnitItem(codeUnit, targetKind, context, fields));
      lastVisited = codeUnit;
      if (scan.stopped()) break;
    }

    if (!scan.stopped()) {
      CodeUnit boundaryCandidate = lastVisited != null ? lastVisited : firstCodeUnit;
      if (reachesWindowEnd(boundaryCandidate, range, forward)) {
        scan.anchorCompletedEnd(AddressUtil.canonicalAddress(boundaryCandidate.getAddress()));
      } else {
        CodeUnit lastCodeUnit = lastCodeUnitInWindow(listing, range, forward);
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
      Listing listing, AddressScanRanges.Resolved range, Address cursor, boolean forward) {
    if (forward) {
      if (cursor != null && cursor.compareTo(range.start()) >= 0) {
        if (cursor.compareTo(range.end()) >= 0) {
          return null;
        }
        CodeUnit afterCursor = listing.getCodeUnitAfter(cursor);
        return afterCursor != null && !range.afterEnd(afterCursor.getAddress())
            ? afterCursor
            : null;
      }
      CodeUnit atStart = listing.getCodeUnitAt(range.start());
      CodeUnit first = atStart != null ? atStart : listing.getCodeUnitAfter(range.start());
      return first != null && !range.afterEnd(first.getAddress()) ? first : null;
    }

    if (cursor != null && cursor.compareTo(range.end()) <= 0) {
      if (cursor.compareTo(range.start()) <= 0) {
        return null;
      }
      CodeUnit beforeCursor = listing.getCodeUnitBefore(cursor);
      return beforeCursor != null && beforeCursor.getAddress().compareTo(range.start()) >= 0
          ? beforeCursor
          : null;
    }
    CodeUnit containingEnd = listing.getCodeUnitContaining(range.end());
    CodeUnit first = containingEnd != null ? containingEnd : listing.getCodeUnitBefore(range.end());
    return first != null && first.getAddress().compareTo(range.start()) >= 0 ? first : null;
  }

  private static CodeUnit lastCodeUnitInWindow(
      Listing listing, AddressScanRanges.Resolved range, boolean forward) {
    if (forward) {
      CodeUnit containingEnd = listing.getCodeUnitContaining(range.end());
      CodeUnit last =
          containingEnd != null ? containingEnd : listing.getCodeUnitBefore(range.end());
      return last != null && range.includes(last.getAddress()) ? last : null;
    }
    CodeUnit atStart = listing.getCodeUnitAt(range.start());
    CodeUnit last = atStart != null ? atStart : listing.getCodeUnitAfter(range.start());
    return last != null && range.includes(last.getAddress()) ? last : null;
  }

  private static boolean reachesWindowEnd(
      CodeUnit codeUnit, AddressScanRanges.Resolved range, boolean forward) {
    if (forward) {
      Address maxAddress = codeUnit.getMaxAddress();
      return maxAddress != null && maxAddress.compareTo(range.end()) >= 0;
    }
    return codeUnit.getAddress().compareTo(range.start()) <= 0;
  }
}
