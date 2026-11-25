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
    return JsonUtil.toJson(List.of(from, to, type, operandIndex));
  }
}
