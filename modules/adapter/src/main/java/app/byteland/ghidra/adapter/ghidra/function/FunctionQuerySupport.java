package app.byteland.ghidra.adapter.ghidra.function;

import java.util.Locale;

final class FunctionQuerySupport {
  private FunctionQuerySupport() {}

  static String trimLower(String raw) {
    if (raw == null) {
      return null;
    }
    String text = raw.trim();
    return text.isBlank() ? null : text.toLowerCase(Locale.ROOT);
  }
}
