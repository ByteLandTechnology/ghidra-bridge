package app.byteland.ghidra.adapter.ghidra.reference;

import ghidra.program.model.symbol.Reference;
import java.util.Locale;

final class ReferenceQuerySupport {

  private ReferenceQuerySupport() {}

  static String normalizeDirection(String direction, String fromRaw, String toRaw) {
    String normalizedDirection =
        direction == null || direction.isBlank()
            ? inferDirection(fromRaw, toRaw)
            : direction.toLowerCase(Locale.ROOT);
    if (!"from".equals(normalizedDirection) && !"to".equals(normalizedDirection)) {
      throw new IllegalArgumentException("direction must be from or to");
    }
    return normalizedDirection;
  }

  static void requireTarget(String direction, String fromRaw, String toRaw) {
    String target = "to".equals(direction) ? toRaw : fromRaw;
    if (target == null || target.isBlank()) {
      throw new IllegalArgumentException("from or to is required");
    }
  }

  static boolean matchesType(String requestedType, Reference reference) {
    return requestedType == null
        || requestedType.equalsIgnoreCase(reference.getReferenceType().getName());
  }

  private static String inferDirection(String fromRaw, String toRaw) {
    if (toRaw != null && !toRaw.isBlank() && (fromRaw == null || fromRaw.isBlank())) {
      return "to";
    }
    return "from";
  }
}
