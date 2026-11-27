package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScopeResolver;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

final class ReferenceListQueries {
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;
  private static final String REFERENCE_RESOURCE = "reference";
  private static final String EXT_FROM_CANONICAL =
      AddressUtil.canonicalAddress(Address.EXT_FROM_ADDRESS);

  private final GhidraSession context;
  private final AddressScopeResolver scopes;

  ReferenceListQueries(GhidraSession context) {
    this(context, new AddressScopeResolver(context));
  }

  ReferenceListQueries(GhidraSession context, AddressScopeResolver scopes) {
    this.context = context;
    this.scopes = scopes;
  }

  Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    return listReferences(
        fromRaw,
        toRaw,
        type,
        direction,
        null,
        new AddressScanOptions(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS),
        limit,
        cursor);
  }

  Page<ReferenceResource> listReferences(
      String fromRaw,
      String toRaw,
      String type,
      String direction,
      FlowOverrideScope scope,
      AddressScanOptions options,
      int limit,
      String cursor) {
    int normalizedLimit = Page.clampLimit(limit);
    String normalizedDirection =
        ReferenceQuerySupport.normalizeDirection(direction, fromRaw, toRaw);
    boolean incoming = "to".equals(normalizedDirection);
    Address fromFilter =
        fromRaw == null || fromRaw.isBlank() ? null : parseAddress(fromRaw);
    Address toFilter = toRaw == null || toRaw.isBlank() ? null : parseAddress(toRaw);
    Address primaryAnchor = incoming ? toFilter : fromFilter;

    if (scope == null
        && options.start() == null
        && options.end() == null
        && primaryAnchor != null) {
      return listSingleAnchor(
          primaryAnchor,
          normalizedDirection,
          incoming,
          fromFilter,
          toFilter,
          type,
          normalizedLimit,
          cursor);
    }
    return listScopedOrRange(
        incoming, fromFilter, toFilter, type, scope, options, normalizedLimit, cursor);
  }

  private Page<ReferenceResource> listSingleAnchor(
      Address anchor,
      String normalizedDirection,
      boolean incoming,
      Address fromFilter,
      Address toFilter,
      String type,
      int limit,
      String cursor) {
    long startedNanos = System.nanoTime();
    String canonicalAnchor = AddressUtil.canonicalAddress(anchor);
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || !context.canCacheSnapshots()) {
      return selectReferencesBounded(
          startedNanos, anchor, canonicalAnchor, incoming, fromFilter, toFilter, type, limit, cursor);
    }

    Program snapshotProgram = context.currentProgramOrNull();
    QuerySnapshotCache snapshots = context.querySnapshots();
    long clearEpoch = snapshots.clearEpoch();
    long modNumber = context.modificationNumber();
    String normalizedType = type == null ? null : type.toUpperCase(Locale.ROOT);
    String canonicalFrom = fromFilter == null ? null : AddressUtil.canonicalAddress(fromFilter);
    String canonicalTo = toFilter == null ? null : AddressUtil.canonicalAddress(toFilter);
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            REFERENCE_RESOURCE,
            modNumber,
            normalizedDirection,
            canonicalAnchor,
            canonicalFrom,
            canonicalTo,
            normalizedType);
    String[] sortedKeys = snapshots.get(cacheKey);
    Boolean scannedAny = null;
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      boolean visitedAny = false;
      for (Reference reference : context.references(anchor, incoming)) {
        visitedAny = true;
        if (!ReferenceQuerySupport.matchesType(type, reference)
            || !matchesEndpoint(fromFilter, reference.getFromAddress())
            || !matchesEndpoint(toFilter, reference.getToAddress())) {
          continue;
        }
        keys.add(ReferenceDescriptions.referenceKey(reference, anchor, canonicalAnchor).encoded());
      }
      scannedAny = visitedAny;
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectReferencesBounded(
            startedNanos,
            anchor,
            canonicalAnchor,
            incoming,
            fromFilter,
            toFilter,
            type,
            limit,
            cursor);
      }
      if (context.currentProgramOrNull() == snapshotProgram
          && context.modificationNumber() == modNumber) {
        snapshots.putIfUnchanged(clearEpoch, cacheKey, sortedKeys);
      }
    }

    FunctionManager[] functionManagerHolder = new FunctionManager[1];
    AddressResource.FunctionSummary[] anchorFunctionHolder =
        new AddressResource.FunctionSummary[1];
    boolean[] summariesInitialized = new boolean[1];
    Page<ReferenceResource> selected =
        QuerySnapshotCache.slice(
            sortedKeys,
            limit,
            cursor,
            encodedKey -> resolveReference(anchor, incoming, encodedKey),
            reference -> {
              if (!summariesInitialized[0]) {
                functionManagerHolder[0] = context.currentProgram().getFunctionManager();
                anchorFunctionHolder[0] =
                    ReferenceDescriptions.functionSummary(functionManagerHolder[0], anchor);
                summariesInitialized[0] = true;
              }
              return ReferenceDescriptions.describe(
                  reference,
                  functionManagerHolder[0],
                  anchor,
                  canonicalAnchor,
                  anchorFunctionHolder[0]);
            });
    boolean visitedAny =
        scannedAny != null
            ? scannedAny
            : sortedKeys.length > 0 || context.references(anchor, incoming).iterator().hasNext();
    return wrapSingleAnchorScan(startedNanos, canonicalAnchor, visitedAny, selected);
  }

  private Page<ReferenceResource> selectReferencesBounded(
      long startedNanos,
      Address anchor,
      String canonicalAnchor,
      boolean incoming,
      Address fromFilter,
      Address toFilter,
      String type,
      int limit,
      String cursor) {
    Page.Selector<Reference> selector = Page.selector(limit, cursor);
    boolean visitedAny = false;
    for (Reference reference : context.references(anchor, incoming)) {
      visitedAny = true;
      if (!ReferenceQuerySupport.matchesType(type, reference)
          || !matchesEndpoint(fromFilter, reference.getFromAddress())
          || !matchesEndpoint(toFilter, reference.getToAddress())) {
        continue;
      }
      String encoded =
          ReferenceDescriptions.referenceKey(reference, anchor, canonicalAnchor).encoded();
      selector.offer(encoded, reference);
    }
    FunctionManager functionManager =
        selector.retainedCount() == 0 ? null : context.currentProgram().getFunctionManager();
    AddressResource.FunctionSummary anchorFunction =
        ReferenceDescriptions.functionSummary(functionManager, anchor);
    Page<ReferenceResource> selected =
        selector.finish(
            reference ->
                ReferenceDescriptions.describe(
                    reference, functionManager, anchor, canonicalAnchor, anchorFunction));
    return wrapSingleAnchorScan(startedNanos, canonicalAnchor, visitedAny, selected);
  }

  private static Page<ReferenceResource> wrapSingleAnchorScan(
      long startedNanos,
      String canonicalAnchor,
      boolean visitedAny,
      Page<ReferenceResource> selected) {
    long elapsedMs = Math.max(0L, (System.nanoTime() - startedNanos) / NANOS_PER_MILLISECOND);
    boolean complete = selected.nextCursor() == null;
    String scannedBound = visitedAny ? canonicalAnchor : null;
    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            canonicalAnchor,
            canonicalAnchor,
            scannedBound,
            scannedBound,
            complete,
            complete ? ScanProgress.StopReason.COMPLETED : ScanProgress.StopReason.LIMIT,
            elapsedMs);
    return Page.scanned(selected.items(), selected.limit(), selected.nextCursor(), progress);
  }

  private Page<ReferenceResource> listScopedOrRange(
      boolean incoming,
      Address fromFilter,
      Address toFilter,
      String type,
      FlowOverrideScope scope,
      AddressScanOptions options,
      int limit,
      String cursor) {
    CursorPosition cursorPosition = parseCursor(cursor);
    AddressSet targetAddresses = resolveTargetAddresses(scope, options);
    Address primaryAnchor = incoming ? toFilter : fromFilter;
    if (primaryAnchor != null) {
      targetAddresses = targetAddresses.intersect(new AddressSet(primaryAnchor, primaryAnchor));
    }
    String requestedStart =
        targetAddresses.isEmpty()
            ? options.start()
            : AddressUtil.canonicalAddress(targetAddresses.getMinAddress());
    String requestedEnd =
        targetAddresses.isEmpty()
            ? options.end()
            : AddressUtil.canonicalAddress(targetAddresses.getMaxAddress());
    AddressSet iterationSet =
        cursorPosition == null
            ? targetAddresses
            : tailFrom(targetAddresses, cursorPosition.address());

    BoundedAddressScan<ReferenceResource> scan =
        BoundedAddressScan.start(limit, options.timeoutMs(), requestedStart, requestedEnd);
    ReferenceManager refManager = context.currentProgram().getReferenceManager();
    FunctionManager functionManager = context.currentProgram().getFunctionManager();
    AddressIterator addresses =
        incoming
            ? refManager.getReferenceDestinationIterator(iterationSet, true)
            : refManager.getReferenceSourceIterator(iterationSet, true);
    int matchedCount = 0;

    for (Address anchor : addresses) {
      if (cursorPosition != null && anchor.compareTo(cursorPosition.address()) < 0) {
        continue;
      }
      String anchorCanonical = AddressUtil.canonicalAddress(anchor);
      String anchorCursor =
          cursorPosition != null && anchor.equals(cursorPosition.address())
              ? cursorPosition.key()
              : null;
      int needed = limit - matchedCount;
      Page.Selector<Reference> selector = Page.selector(needed, anchorCursor);
      String maxUnmatchedKey = null;
      for (Reference reference : context.references(anchor, incoming)) {
        String encoded =
            ReferenceDescriptions.referenceKey(reference, anchor, anchorCanonical).encoded();
        if (anchorCursor != null && encoded.compareTo(anchorCursor) <= 0) {
          continue;
        }
        if (ReferenceQuerySupport.matchesType(type, reference)
            && matchesEndpoint(fromFilter, reference.getFromAddress())
            && matchesEndpoint(toFilter, reference.getToAddress())) {
          selector.offer(encoded, reference);
        } else if (maxUnmatchedKey == null || encoded.compareTo(maxUnmatchedKey) > 0) {
          maxUnmatchedKey = encoded;
        }
      }
      if (selector.retainedCount() == 0) {
        if (maxUnmatchedKey != null) {
          scan.visit(anchorCanonical, CompositeCursor.key(anchorCanonical, maxUnmatchedKey), null);
        }
      } else {
        AddressResource.FunctionSummary anchorFunction =
            ReferenceDescriptions.functionSummary(functionManager, anchor);
        Page<DescribedReference> winners =
            selector.finish(
                (reference, encoded) ->
                    new DescribedReference(
                        encoded,
                        ReferenceDescriptions.describe(
                            reference, functionManager, anchor, anchorCanonical, anchorFunction)));
        for (DescribedReference winner : winners.items()) {
          scan.visit(
              anchorCanonical,
              CompositeCursor.key(anchorCanonical, winner.encodedKey()),
              winner.resource());
          matchedCount++;
          if (scan.stopped()) break;
        }
      }
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private AddressSet resolveTargetAddresses(FlowOverrideScope scope, AddressScanOptions options) {
    if (scope == null) {
      AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
      return new AddressSet(range.start(), range.end());
    }
    AddressSet scoped = new AddressSet(scopes.resolve(scope));
    if (options.start() != null || options.end() != null) {
      AddressScanRanges.Resolved clip = AddressScanRanges.resolve(context, options, true);
      scoped = scoped.intersect(new AddressSet(clip.start(), clip.end()));
    }
    return scoped;
  }

  private AddressSet tailFrom(AddressSet addresses, Address cursor) {
    if (addresses.isEmpty()) {
      return addresses;
    }
    Address max = addresses.getMaxAddress();
    if (cursor.compareTo(max) > 0) {
      return new AddressSet();
    }
    if (cursor.getAddressSpace().equals(max.getAddressSpace())) {
      return addresses.intersect(new AddressSet(cursor, max));
    }
    return addresses.intersect(new AddressSet(context.currentProgram(), cursor, max));
  }

  private static boolean matchesEndpoint(Address expected, Address actual) {
    return expected == null || expected.equals(actual);
  }

  private CursorPosition parseCursor(String cursor) {
    CompositeCursor parts = CompositeCursor.parse(cursor, "references");
    if (parts == null) return null;
    return new CursorPosition(parseAddress(parts.address()), parts.secondary());
  }

  private record DescribedReference(String encodedKey, ReferenceResource resource) {}

  private record CursorPosition(Address address, String key) {}

  private Reference resolveReference(Address anchor, boolean incoming, String encodedKey) {
    ReferenceCursorKey key = ReferenceCursorKey.decode(encodedKey);
    if (incoming) {
      Address fromAddress =
          EXT_FROM_CANONICAL.equals(key.from())
              ? Address.EXT_FROM_ADDRESS
              : tryParseAddress(key.from());
      if (fromAddress == null) {
        return null;
      }
      Reference exact = context.reference(fromAddress, anchor, key.operandIndex());
      if (exact != null && matchesDecodedKey(exact, key)) {
        return exact;
      }
      for (Reference candidate : context.references(fromAddress, false)) {
        if (matchesDecodedKey(candidate, key)) {
          return candidate;
        }
      }
      return null;
    }

    for (Reference candidate : context.references(anchor, false)) {
      if (matchesDecodedKey(candidate, key)) {
        return candidate;
      }
    }
    return null;
  }

  private static boolean matchesDecodedKey(Reference candidate, ReferenceCursorKey key) {
    return candidate.getOperandIndex() == key.operandIndex()
        && key.type().equals(candidate.getReferenceType().getName())
        && key.from().equals(AddressUtil.canonicalAddress(candidate.getFromAddress()))
        && key.to().equals(AddressUtil.canonicalAddress(candidate.getToAddress()));
  }

  private Address tryParseAddress(String rawAddress) {
    try {
      return parseAddress(rawAddress);
    } catch (IllegalArgumentException ignored) {
      return null;
    }
  }
  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
