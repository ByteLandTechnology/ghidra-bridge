package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;

final class ReferenceListQueries {
  private final GhidraSession context;

  ReferenceListQueries(GhidraSession context) {
    this.context = context;
  }

  Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    return listReferences(fromRaw, null, null, toRaw, type, direction, limit, cursor);
  }

  Page<ReferenceResource> listReferences(
      String fromRaw,
      String entryRaw,
      ReferenceService.RangeFilter fromRange,
      String toRaw,
      String type,
      String direction,
      int limit,
      String cursor) {
    int normalizedLimit = Page.clampLimit(limit);
    String normalizedDirection =
        ReferenceQuerySupport.normalizeDirection(direction, fromRaw, entryRaw, fromRange, toRaw);
    ReferenceQuerySupport.requireTarget(
        normalizedDirection, fromRaw, entryRaw, fromRange, toRaw);

    List<KeyedReference> matched = new ArrayList<>();
    if ("to".equals(normalizedDirection)) {
      collectAnchorReferences(parseAddress(toRaw), true, type, matched);
    } else if (fromRaw != null && !fromRaw.isBlank()) {
      collectAnchorReferences(parseAddress(fromRaw), false, type, matched);
    } else {
      AddressSetView sourceAddresses =
          entryRaw != null && !entryRaw.isBlank()
              ? resolveFunctionBody(entryRaw)
              : resolveRange(fromRange);
      collectRangeReferences(sourceAddresses, type, matched);
    }

    matched.sort(Comparator.comparing(KeyedReference::encodedKey));
    String nextCursor = null;
    List<KeyedReference> pageReferences = new ArrayList<>();
    for (KeyedReference keyed : matched) {
      if (cursor != null && !cursor.isBlank() && keyed.encodedKey().compareTo(cursor) <= 0) {
        continue;
      }
      pageReferences.add(keyed);
      if (pageReferences.size() > normalizedLimit) break;
    }
    if (pageReferences.size() > normalizedLimit) {
      pageReferences.remove(pageReferences.size() - 1);
      nextCursor = pageReferences.getLast().encodedKey();
    }
    List<ReferenceResource> items =
        pageReferences.stream()
            .map(keyed -> ReferenceDescriptions.describe(keyed.reference()))
            .toList();
    return Page.of(items, normalizedLimit, nextCursor);
  }

  private void collectAnchorReferences(
      Address anchor, boolean to, String type, List<KeyedReference> matched) {
    for (Reference reference : context.references(anchor, to)) {
      addIfMatched(type, reference, matched);
    }
  }

  private void collectRangeReferences(
      AddressSetView sourceAddresses, String type, List<KeyedReference> matched) {
    ReferenceManager referenceManager = context.currentProgram().getReferenceManager();
    AddressIterator sources = referenceManager.getReferenceSourceIterator(sourceAddresses, true);
    while (sources.hasNext()) {
      Address fromAddress = sources.next();
      for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
        addIfMatched(type, reference, matched);
      }
    }
  }

  private static void addIfMatched(
      String type, Reference reference, List<KeyedReference> matched) {
    if (!ReferenceQuerySupport.matchesType(type, reference)) {
      return;
    }
    String encoded = ReferenceDescriptions.referenceKey(reference).encoded();
    matched.add(new KeyedReference(reference, encoded));
  }

  private AddressSetView resolveFunctionBody(String entryRaw) {
    Address entry = parseAddress(entryRaw);
    Function function = context.currentProgram().getFunctionManager().getFunctionAt(entry);
    if (function == null) {
      throw new NoSuchElementException("no function at entry address: " + entryRaw);
    }
    return function.getBody();
  }

  private AddressSetView resolveRange(ReferenceService.RangeFilter fromRange) {
    Address start = parseAddress(fromRange.start());
    Address end = parseAddress(fromRange.end());
    if (!start.getAddressSpace().equals(end.getAddressSpace())) {
      throw new IllegalArgumentException("start and end must be in the same address space");
    }
    if (start.compareTo(end) > 0) {
      throw new IllegalArgumentException("start must not be greater than end");
    }
    return new AddressSet(start, end);
  }

  private record KeyedReference(Reference reference, String encodedKey) {}

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
