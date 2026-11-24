package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

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

    boolean incoming = "to".equals(normalizedDirection);
    String target = incoming ? toRaw : fromRaw;
    Address anchor = parseAddress(target);
    String canonicalAnchor = AddressUtil.canonicalAddress(anchor);
    Page.Selector<Reference> selector = Page.selector(normalizedLimit, cursor);
    Iterable<Reference> refs = context.references(anchor, incoming);
    for (Reference reference : refs) {
      if (!ReferenceQuerySupport.matchesType(type, reference)) {
        continue;
      }
      String encoded =
          ReferenceDescriptions.referenceKey(reference, anchor, canonicalAnchor).encoded();
      selector.offer(encoded, reference);
    }
    return selector.finish(
        reference -> ReferenceDescriptions.describe(reference, anchor, canonicalAnchor));
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
