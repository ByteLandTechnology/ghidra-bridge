package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.JsonUtil;
import java.util.List;
import java.util.Objects;

record ReferenceCursorKey(String from, String to, String type, int operandIndex)
    implements Comparable<ReferenceCursorKey> {

  ReferenceCursorKey {
    Objects.requireNonNull(from, "from");
    Objects.requireNonNull(to, "to");
    Objects.requireNonNull(type, "type");
  }

  String encoded() {
    return JsonUtil.toJson(List.of(from, to, type, operandIndex));
  }

  @Override
  public int compareTo(ReferenceCursorKey other) {
    return encoded().compareTo(other.encoded());
  }

  int compareToEncoded(String cursor) {
    return encoded().compareTo(cursor);
  }
}
