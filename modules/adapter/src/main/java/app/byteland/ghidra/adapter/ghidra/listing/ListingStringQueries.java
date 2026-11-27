package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.listing.ListingService.StringQuery;
import app.byteland.ghidra.service.listing.StringResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.function.Supplier;

/**
 * Queries defined strings and optional candidate strings in undefined initialized memory.
 */
final class ListingStringQueries {
  private final GhidraSession context;

  ListingStringQueries(GhidraSession context) {
    this.context = context;
  }

  Page<StringResource> listStrings(StringQuery query) {
    StringFilterMatcher matcher = StringFilterMatcher.compile(query);
    int normalizedLimit = Page.clampLimit(query.limit());
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);

    BoundedAddressScan<StringResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());

    Address effectiveStart = resolveEffectiveStart(range, query.cursor());
    if (effectiveStart == null) {
      return scan.finish();
    }

    Program program = context.currentProgram();
    Address iterEnd =
        range.end() != null ? range.end() : effectiveStart.getAddressSpace().getMaxAddress();

    String previousCursor =
        query.cursor() == null
            ? null
            : AddressUtil.canonicalAddress(context.parseAddress(query.cursor()));

    DefinedStringStream definedStream = new DefinedStringStream(program, effectiveStart, iterEnd);
    CandidateStringScanner candidateScanner =
        query.includeCandidates()
            ? new CandidateStringScanner(
                program,
                range.start(),
                effectiveStart,
                iterEnd,
                previousCursor,
                matcher.minCandidateLength(),
                scan)
            : null;

    while (!scan.stopped()) {
      StreamItem nextDefined = definedStream.peek();
      Address candidateLimit = nextDefined != null ? nextDefined.address() : iterEnd;
      StreamItem nextCandidate =
          candidateScanner == null ? null : candidateScanner.peekUpTo(candidateLimit);
      if (scan.stopped() || (nextDefined == null && nextCandidate == null)) {
        break;
      }

      StreamItem chosen =
          takeNextInAddressOrder(definedStream, candidateScanner, nextDefined, nextCandidate);

      if (scan.hasTimedOut()) {
        scan.stopOnTimeout(
            chosen.canonicalAddress(),
            fallbackBefore(chosen.address(), range.start(), previousCursor));
        break;
      }

      boolean matched;
      try {
        matched =
            matcher.matches(
                chosen.value(), chosen.encoding(), scan.nanoTimeSupplier(), scan.deadlineNanos());
      } catch (StringFilterMatcher.RegexTimeoutException timeout) {
        scan.stopOnTimeout(
            chosen.canonicalAddress(),
            fallbackBefore(chosen.address(), range.start(), previousCursor));
        break;
      }

      scan.visit(
          chosen.canonicalAddress(),
          chosen.resumeCursor(),
          matched ? chosen.toResource() : null);
      previousCursor = chosen.resumeCursor();
    }

    return scan.finish();
  }

  private static StreamItem takeNextInAddressOrder(
      DefinedStringStream definedStream,
      CandidateStringScanner candidateScanner,
      StreamItem nextDefined,
      StreamItem nextCandidate) {
    if (nextCandidate == null) {
      return definedStream.take();
    }
    if (nextDefined == null) {
      return candidateScanner.take();
    }
    int cmp = nextDefined.address().compareTo(nextCandidate.address());
    if (cmp <= 0) {
      StreamItem chosen = definedStream.take();
      if (cmp == 0) {
        candidateScanner.take();
      }
      return chosen;
    }
    return candidateScanner.take();
  }

  private Address resolveEffectiveStart(AddressScanRanges.Resolved range, String cursorRaw) {
    if (cursorRaw == null) {
      return range.start();
    }
    Address cursor = context.parseAddress(cursorRaw);
    if (!cursor.getAddressSpace().equals(range.start().getAddressSpace())) {
      throw new IllegalArgumentException("cursor must be in the scan address space");
    }
    if (range.end() != null && cursor.compareTo(range.end()) >= 0) {
      return null;
    }
    Address next = cursor.next();
    if (next == null || !next.getAddressSpace().equals(cursor.getAddressSpace())) {
      return null;
    }
    return next.compareTo(range.start()) > 0 ? next : range.start();
  }

  static String fallbackBefore(Address current, Address rangeStart, String previousCursor) {
    if (previousCursor != null) {
      return previousCursor;
    }
    if (current.compareTo(rangeStart) > 0) {
      Address prev = current.previous();
      if (prev != null && prev.getAddressSpace().equals(current.getAddressSpace())) {
        return AddressUtil.canonicalAddress(prev);
      }
    }
    return null;
  }

  record StreamItem(
      Address address,
      String canonicalAddress,
      String resumeCursor,
      int byteLength,
      String value,
      String encoding,
      boolean defined,
      Supplier<DataTypeReference> dataTypeSupplier) {
    StringResource toResource() {
      return new StringResource(
          canonicalAddress, byteLength, value, encoding, defined, dataTypeSupplier.get());
    }
  }
}
