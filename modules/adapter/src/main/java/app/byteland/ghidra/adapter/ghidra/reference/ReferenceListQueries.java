package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.List;

final class ReferenceListQueries {
  private final GhidraSession context;

  ReferenceListQueries(GhidraSession context) {
    this.context = context;
  }

  Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    int normalizedLimit = Page.clampLimit(limit);
    String normalizedDirection =
        ReferenceQuerySupport.normalizeDirection(direction, fromRaw, toRaw);
    ReferenceQuerySupport.requireTarget(normalizedDirection, fromRaw, toRaw);

    String target = "to".equals(normalizedDirection) ? toRaw : fromRaw;
    Address anchor = parseAddress(target);
    List<KeyedReference> matched = new ArrayList<>();
    String nextCursor = null;
    Iterable<Reference> refs = context.references(anchor, "to".equals(normalizedDirection));
    for (Reference reference : refs) {
      if (!ReferenceQuerySupport.matchesType(type, reference)) {
        continue;
      }
      String encoded = ReferenceDescriptions.referenceKey(reference).encoded();
      matched.add(new KeyedReference(reference, encoded));
    }
    matched.sort(java.util.Comparator.comparing(KeyedReference::encodedKey));
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

  private record KeyedReference(Reference reference, String encodedKey) {}

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
