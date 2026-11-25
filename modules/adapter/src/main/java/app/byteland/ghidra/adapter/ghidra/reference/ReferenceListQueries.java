package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

final class ReferenceListQueries {
  private static final String REFERENCE_RESOURCE = "reference";
  private static final String EXT_FROM_CANONICAL =
      AddressUtil.canonicalAddress(Address.EXT_FROM_ADDRESS);

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
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || !context.canCacheSnapshots()) {
      return selectReferencesBounded(
          anchor, canonicalAnchor, incoming, type, normalizedLimit, cursor);
    }

    QuerySnapshotCache snapshots = context.querySnapshots();
    long clearEpoch = snapshots.clearEpoch();
    long modNumber = context.modificationNumber();
    String normalizedType = type == null ? null : type.toUpperCase(Locale.ROOT);
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            REFERENCE_RESOURCE, modNumber, normalizedDirection, canonicalAnchor, normalizedType);
    String[] sortedKeys = snapshots.get(cacheKey);
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      for (Reference reference : context.references(anchor, incoming)) {
        if (!ReferenceQuerySupport.matchesType(type, reference)) {
          continue;
        }
        keys.add(ReferenceDescriptions.referenceKey(reference, anchor, canonicalAnchor).encoded());
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectReferencesBounded(
            anchor, canonicalAnchor, incoming, type, normalizedLimit, cursor);
      }
      if (context.modificationNumber() == modNumber) {
        snapshots.putIfUnchanged(clearEpoch, cacheKey, sortedKeys);
      }
    }
    return QuerySnapshotCache.slice(
        sortedKeys,
        normalizedLimit,
        cursor,
        encodedKey -> resolveReference(anchor, incoming, encodedKey),
        reference -> ReferenceDescriptions.describe(reference, anchor, canonicalAnchor));
  }

  private Page<ReferenceResource> selectReferencesBounded(
      Address anchor,
      String canonicalAnchor,
      boolean incoming,
      String type,
      int normalizedLimit,
      String cursor) {
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
