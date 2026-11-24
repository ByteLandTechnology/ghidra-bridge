package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.service.reference.ReferenceService;
import ghidra.program.model.symbol.Reference;
import java.util.Locale;

final class ReferenceQuerySupport {

  private ReferenceQuerySupport() {}

  static String normalizeDirection(
      String direction,
      String fromRaw,
      String entryRaw,
      ReferenceService.RangeFilter fromRange,
      String toRaw) {
    String normalizedDirection =
        direction == null || direction.isBlank()
            ? inferDirection(fromRaw, entryRaw, fromRange, toRaw)
            : direction.toLowerCase(Locale.ROOT);
    if (!"from".equals(normalizedDirection) && !"to".equals(normalizedDirection)) {
      throw new IllegalArgumentException("direction must be from or to");
    }
    return normalizedDirection;
  }

  static void requireTarget(
      String direction,
      String fromRaw,
      String entryRaw,
      ReferenceService.RangeFilter fromRange,
      String toRaw) {
    boolean hasFrom = hasText(fromRaw);
    boolean hasEntry = hasText(entryRaw);
    boolean hasRange = fromRange != null;
    boolean hasTo = hasText(toRaw);
    if ("to".equals(direction)) {
      if (hasFrom || hasEntry || hasRange) {
        throw new IllegalArgumentException(
            "from, entry, and from_range are not valid when direction is to");
      }
      if (!hasTo) {
        throw new IllegalArgumentException("to is required when direction is to");
      }
      return;
    }
    if (hasTo) {
      throw new IllegalArgumentException("to is not valid when direction is from");
    }
    int sourceSelectors = (hasFrom ? 1 : 0) + (hasEntry ? 1 : 0) + (hasRange ? 1 : 0);
    if (sourceSelectors == 0) {
      throw new IllegalArgumentException(
          "from, entry, or from_range is required when direction is from");
    }
    if (sourceSelectors > 1) {
      throw new IllegalArgumentException("specify only one of from, entry, or from_range");
    }
    if (hasRange && (!hasText(fromRange.start()) || !hasText(fromRange.end()))) {
      throw new IllegalArgumentException("from_range.start and from_range.end are required");
    }
  }

  static boolean matchesType(String requestedType, Reference reference) {
    return requestedType == null
        || requestedType.equalsIgnoreCase(reference.getReferenceType().getName());
  }

  private static String inferDirection(
      String fromRaw,
      String entryRaw,
      ReferenceService.RangeFilter fromRange,
      String toRaw) {
    if (hasText(toRaw) && !hasText(fromRaw) && !hasText(entryRaw) && fromRange == null) {
      return "to";
    }
    return "from";
  }

  private static boolean hasText(String value) {
    return value != null && !value.isBlank();
  }
}
