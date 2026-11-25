package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.JsonUtil;
import java.util.List;
import java.util.Objects;

record ReferenceCursorKey(String from, String to, String type, int operandIndex) {

  ReferenceCursorKey {
    Objects.requireNonNull(from, "from");
    Objects.requireNonNull(to, "to");
    Objects.requireNonNull(type, "type");
  }

  String encoded() {
    return encode(from, to, type, operandIndex);
  }

  static String encode(String from, String to, String type, int operandIndex) {
    Objects.requireNonNull(from, "from");
    Objects.requireNonNull(to, "to");
    Objects.requireNonNull(type, "type");
    if (needsJsonEscaping(from) || needsJsonEscaping(to) || needsJsonEscaping(type)) {
      return JsonUtil.toJson(List.of(from, to, type, operandIndex));
    }
    StringBuilder builder = new StringBuilder(from.length() + to.length() + type.length() + 24);
    builder
        .append("[\"")
        .append(from)
        .append("\",\"")
        .append(to)
        .append("\",\"")
        .append(type)
        .append("\",")
        .append(operandIndex)
        .append(']');
    return builder.toString();
  }

  static ReferenceCursorKey decode(String encoded) {
    Object parsed = JsonUtil.parse(encoded);
    if (!(parsed instanceof List<?> parts) || parts.size() != 4) {
      throw new IllegalArgumentException("invalid reference cursor key");
    }
    if (!(parts.get(0) instanceof String from)
        || !(parts.get(1) instanceof String to)
        || !(parts.get(2) instanceof String type)
        || !(parts.get(3) instanceof Number operandIndex)) {
      throw new IllegalArgumentException("invalid reference cursor key fields");
    }
    return new ReferenceCursorKey(from, to, type, operandIndex.intValue());
  }

  private static boolean needsJsonEscaping(String value) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch < 0x20 || ch == '"' || ch == '\\') {
        return true;
      }
    }
    return false;
  }
}
