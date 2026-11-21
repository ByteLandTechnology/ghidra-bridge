package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScopeResolver;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

final class ReferenceListQueries {
  private final GhidraSession context;
  private final AddressScopeResolver scopes;

  ReferenceListQueries(GhidraSession context, AddressScopeResolver scopes) {
    this.context = context;
    this.scopes = scopes;
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
    Address fromFilter = fromRaw == null ? null : parseAddress(fromRaw);
    Address toFilter = toRaw == null ? null : parseAddress(toRaw);
    Address primaryAnchor = incoming ? toFilter : fromFilter;

    if (scope == null
        && options.start() == null
        && options.end() == null
        && primaryAnchor != null) {
      return listSingleAnchor(
          primaryAnchor, incoming, fromFilter, toFilter, type, options, normalizedLimit, cursor);
    }
    return listScopedOrRange(
        incoming, fromFilter, toFilter, type, scope, options, normalizedLimit, cursor);
  }

  private Page<ReferenceResource> listSingleAnchor(
      Address anchor,
      boolean incoming,
      Address fromFilter,
      Address toFilter,
      String type,
      AddressScanOptions options,
      int limit,
      String cursor) {
    String anchorText = AddressUtil.canonicalAddress(anchor);
    List<KeyedReference> candidates = new ArrayList<>();
    for (Reference reference : context.references(anchor, incoming)) {
      candidates.add(
          new KeyedReference(reference, ReferenceDescriptions.referenceKey(reference).encoded()));
    }
    candidates.sort(Comparator.comparing(KeyedReference::encodedKey));

    BoundedAddressScan<ReferenceResource> scan =
        BoundedAddressScan.start(limit, options.timeoutMs(), anchorText, anchorText);
    for (KeyedReference keyed : candidates) {
      if (cursor != null && !cursor.isBlank() && keyed.encodedKey().compareTo(cursor) <= 0) {
        continue;
      }
      boolean matches =
          ReferenceQuerySupport.matchesType(type, keyed.reference())
              && matchesEndpoint(fromFilter, keyed.reference().getFromAddress())
              && matchesEndpoint(toFilter, keyed.reference().getToAddress());
      ReferenceResource item =
          matches ? ReferenceDescriptions.describe(keyed.reference(), context) : null;
      scan.visit(anchorText, keyed.encodedKey(), item);
      if (scan.stopped()) break;
    }
    return scan.finish();
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
    AddressIterator addresses =
        incoming
            ? refManager.getReferenceDestinationIterator(iterationSet, true)
            : refManager.getReferenceSourceIterator(iterationSet, true);

    for (Address anchor : addresses) {
      List<KeyedReference> atAnchor = referencesAtAnchor(refManager, anchor, incoming);
      String anchorCanonical = AddressUtil.canonicalAddress(anchor);
      for (KeyedReference keyed : atAnchor) {
        if (cursorPosition != null && compare(anchor, keyed.encodedKey(), cursorPosition) <= 0) {
          continue;
        }
        boolean matches =
            ReferenceQuerySupport.matchesType(type, keyed.reference())
                && matchesEndpoint(fromFilter, keyed.reference().getFromAddress())
                && matchesEndpoint(toFilter, keyed.reference().getToAddress());
        ReferenceResource item =
            matches ? ReferenceDescriptions.describe(keyed.reference(), context) : null;
        scan.visit(
            anchorCanonical, CompositeCursor.key(anchorCanonical, keyed.encodedKey()), item);
        if (scan.stopped()) break;
      }
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private AddressSet resolveTargetAddresses(FlowOverrideScope scope, AddressScanOptions options) {
    if (scope == null) {
      AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
      return new AddressSet(context.currentProgram(), range.start(), range.end());
    }
    AddressSet scoped = new AddressSet(scopes.resolve(scope));
    if (options.start() != null || options.end() != null) {
      AddressScanRanges.Resolved clip = AddressScanRanges.resolve(context, options, true);
      scoped =
          scoped.intersect(new AddressSet(context.currentProgram(), clip.start(), clip.end()));
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
    return addresses.intersect(new AddressSet(context.currentProgram(), cursor, max));
  }

  private static List<KeyedReference> referencesAtAnchor(
      ReferenceManager refManager, Address anchor, boolean incoming) {
    Iterable<Reference> raw =
        incoming
            ? ReferenceDescriptions.iterable(refManager.getReferencesTo(anchor))
            : Arrays.asList(refManager.getReferencesFrom(anchor));
    List<KeyedReference> keyed = new ArrayList<>();
    for (Reference reference : raw) {
      keyed.add(
          new KeyedReference(reference, ReferenceDescriptions.referenceKey(reference).encoded()));
    }
    keyed.sort(Comparator.comparing(KeyedReference::encodedKey));
    return keyed;
  }

  private static boolean matchesEndpoint(Address expected, Address actual) {
    return expected == null || expected.equals(actual);
  }

  private CursorPosition parseCursor(String cursor) {
    CompositeCursor parts = CompositeCursor.parse(cursor, "references");
    if (parts == null) return null;
    return new CursorPosition(parseAddress(parts.address()), parts.secondary());
  }

  private static int compare(Address address, String key, CursorPosition cursor) {
    int byAddress = address.compareTo(cursor.address());
    return byAddress == 0 ? key.compareTo(cursor.key()) : byAddress;
  }

  private record KeyedReference(Reference reference, String encodedKey) {}

  private record CursorPosition(Address address, String key) {}

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
