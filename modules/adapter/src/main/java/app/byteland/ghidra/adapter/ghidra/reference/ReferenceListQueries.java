package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.listing.ListingFlowOverrideScopes;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService.ReferenceQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

final class ReferenceListQueries {
  private final GhidraSession context;
  private final ListingFlowOverrideScopes scopes;

  ReferenceListQueries(GhidraSession context) {
    this.context = context;
    this.scopes = new ListingFlowOverrideScopes(context);
  }

  Page<ReferenceResource> listReferences(ReferenceQuery query) {
    int normalizedLimit = Page.clampLimit(query.limit());
    String normalizedDirection =
        ReferenceQuerySupport.normalizeDirection(query.direction(), query.from(), query.to());
    boolean inbound = "to".equals(normalizedDirection);

    AddressSetView targetAddresses =
        resolveTargetAddresses(query.selector(), inbound, query.from(), query.to());
    String oppositeRaw = inbound ? query.from() : query.to();
    Address oppositeFilter =
        oppositeRaw == null || oppositeRaw.isBlank() ? null : parseAddress(oppositeRaw);
    CursorPosition cursorPosition = parseCursor(query.cursor(), targetAddresses);

    if (targetAddresses.isEmpty()) {
      return BoundedAddressScan.<ReferenceResource>start(
              normalizedLimit, query.scan().timeoutMs(), null, null)
          .finish();
    }

    String requestedStart = AddressUtil.canonicalAddress(targetAddresses.getMinAddress());
    String requestedEnd = AddressUtil.canonicalAddress(targetAddresses.getMaxAddress());
    BoundedAddressScan<ReferenceResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), requestedStart, requestedEnd);

    AddressSet remaining = new AddressSet(targetAddresses);
    if (cursorPosition != null
        && cursorPosition.address().getAddressSpace().equals(remaining.getMinAddress().getAddressSpace())
        && cursorPosition.address().compareTo(remaining.getMinAddress()) > 0) {
      Address previous = cursorPosition.address().previous();
      if (previous != null) {
        remaining.delete(remaining.getMinAddress(), previous);
      }
    }

    ReferenceManager refManager = context.currentProgram().getReferenceManager();
    AddressIterator anchors =
        inbound
            ? refManager.getReferenceDestinationIterator(remaining, true)
            : refManager.getReferenceSourceIterator(remaining, true);

    while (anchors.hasNext()) {
      Address anchor = anchors.next();
      if (cursorPosition != null && anchor.compareTo(cursorPosition.address()) < 0) {
        continue;
      }
      List<KeyedReference> refsAtAnchor = new ArrayList<>();
      for (Reference reference : context.references(anchor, inbound)) {
        String encoded = ReferenceDescriptions.referenceKey(reference).encoded();
        refsAtAnchor.add(new KeyedReference(reference, encoded));
      }
      refsAtAnchor.sort(Comparator.comparing(KeyedReference::encodedKey));

      String anchorText = AddressUtil.canonicalAddress(anchor);
      for (KeyedReference keyed : refsAtAnchor) {
        if (cursorPosition != null && compare(anchor, keyed.encodedKey(), cursorPosition) <= 0) {
          continue;
        }
        Reference reference = keyed.reference();
        boolean matches =
            ReferenceQuerySupport.matchesType(query.type(), reference)
                && (oppositeFilter == null
                    || oppositeAddress(reference, inbound).equals(oppositeFilter));
        scan.visit(
            anchorText,
            CompositeCursor.key(anchorText, keyed.encodedKey()),
            matches ? ReferenceDescriptions.describe(reference) : null);
        if (scan.stopped()) break;
      }
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private AddressSetView resolveTargetAddresses(
      FlowOverrideScope selector, boolean inbound, String fromRaw, String toRaw) {
    if (selector == null) {
      ReferenceQuerySupport.requireTarget(inbound ? "to" : "from", fromRaw, toRaw);
      Address anchor = parseAddress(inbound ? toRaw : fromRaw);
      return new AddressSet(anchor, anchor);
    }
    String sameSideRaw = inbound ? toRaw : fromRaw;
    if (sameSideRaw != null && !sameSideRaw.isBlank()) {
      throw new IllegalArgumentException(
          "selector conflicts with " + (inbound ? "to" : "from"));
    }
    return scopes.resolve(selector).addresses();
  }

  private CursorPosition parseCursor(String cursorRaw, AddressSetView targetAddresses) {
    CompositeCursor parts = CompositeCursor.parse(cursorRaw, "references");
    if (parts == null) return null;
    Address address = parseAddress(parts.address());
    if (!targetAddresses.contains(address)) {
      throw new IllegalArgumentException("cursor must be inside the selected scope");
    }
    return new CursorPosition(address, parts.secondary());
  }

  private static Address oppositeAddress(Reference reference, boolean inbound) {
    return inbound ? reference.getFromAddress() : reference.getToAddress();
  }

  private static int compare(Address anchor, String encodedKey, CursorPosition cursor) {
    int byAddress = anchor.compareTo(cursor.address());
    return byAddress == 0 ? encodedKey.compareTo(cursor.encodedKey()) : byAddress;
  }

  private record KeyedReference(Reference reference, String encodedKey) {}

  private record CursorPosition(Address address, String encodedKey) {}

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
