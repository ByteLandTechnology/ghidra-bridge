package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
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

    boolean isTo = "to".equals(normalizedDirection);
    String target = isTo ? toRaw : fromRaw;
    Address anchor = parseAddress(target);
    String canonicalAnchor = AddressUtil.canonicalAddress(anchor);
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || !context.canCacheSnapshots()) {
      return selectReferencesBounded(
          anchor, canonicalAnchor, isTo, type, normalizedLimit, cursor);
    }

    long modNumber = context.modificationNumber();
    String normalizedType = type == null ? null : type.toUpperCase(Locale.ROOT);
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            REFERENCE_RESOURCE, modNumber, normalizedDirection, canonicalAnchor, normalizedType);
    String[] sortedKeys = context.querySnapshots().get(cacheKey);
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      for (Reference reference : context.references(anchor, isTo)) {
        if (!ReferenceQuerySupport.matchesType(type, reference)) {
          continue;
        }
        keys.add(encodedKey(reference, anchor, canonicalAnchor, isTo));
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectReferencesBounded(
            anchor, canonicalAnchor, isTo, type, normalizedLimit, cursor);
      }
      if (context.modificationNumber() == modNumber) {
        context.querySnapshots().put(cacheKey, sortedKeys);
      }
    }
    return QuerySnapshotCache.slice(
        sortedKeys,
        normalizedLimit,
        cursor,
        encodedKey -> resolveReference(anchor, isTo, encodedKey),
        reference -> ReferenceDescriptions.describe(reference, anchor, canonicalAnchor));
  }

  private Page<ReferenceResource> selectReferencesBounded(
      Address anchor,
      String canonicalAnchor,
      boolean isTo,
      String type,
      int normalizedLimit,
      String cursor) {
    Page.Selector<Reference> selector = Page.selector(normalizedLimit, cursor);
    for (Reference reference : context.references(anchor, isTo)) {
      if (!ReferenceQuerySupport.matchesType(type, reference)) {
        continue;
      }
      String encoded = encodedKey(reference, anchor, canonicalAnchor, isTo);
      if (selector.acceptsKey(encoded)) {
        selector.offer(encoded, reference);
      }
    }
    return selector.finish(
        reference -> ReferenceDescriptions.describe(reference, anchor, canonicalAnchor));
  }

  private static String encodedKey(
      Reference reference, Address anchor, String canonicalAnchor, boolean isTo) {
    Address fromAddress = reference.getFromAddress();
    Address toAddress = reference.getToAddress();
    String from =
        !isTo && anchor.equals(fromAddress)
            ? canonicalAnchor
            : AddressUtil.canonicalAddress(fromAddress);
    String to =
        isTo && anchor.equals(toAddress)
            ? canonicalAnchor
            : AddressUtil.canonicalAddress(toAddress);
    return ReferenceCursorKey.encode(
        from, to, reference.getReferenceType().getName(), reference.getOperandIndex());
  }

  private Reference resolveReference(Address anchor, boolean isTo, String encodedKey) {
    ReferenceCursorKey key = ReferenceCursorKey.decode(encodedKey);
    if (isTo) {
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
      Program program = context.currentProgramOrNull();
      if (program != null && program.getReferenceManager() != null) {
        for (Reference candidate :
            program.getReferenceManager().getReferencesFrom(fromAddress, key.operandIndex())) {
          if (matchesDecodedKey(candidate, key)) {
            return candidate;
          }
        }
      } else {
        for (Reference candidate : context.references(fromAddress, false)) {
          if (matchesDecodedKey(candidate, key)) {
            return candidate;
          }
        }
      }
      return null;
    }

    Program program = context.currentProgramOrNull();
    if (program != null && program.getReferenceManager() != null) {
      for (Reference candidate :
          program.getReferenceManager().getReferencesFrom(anchor, key.operandIndex())) {
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
