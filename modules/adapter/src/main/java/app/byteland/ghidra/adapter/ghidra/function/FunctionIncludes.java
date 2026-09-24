package app.byteland.ghidra.adapter.ghidra.function;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

final class FunctionIncludes {
  private FunctionIncludes() {}

  static Set<String> parse(String raw) {
    if (raw == null || raw.isBlank()) {
      return Set.of();
    }
    Set<String> includes = new LinkedHashSet<>();
    int start = 0;
    while (start < raw.length()) {
      int separator = raw.indexOf(',', start);
      int end = separator < 0 ? raw.length() : separator;
      String part = raw.substring(start, end);
      String normalized = part.trim().toLowerCase(Locale.ROOT);
      if (!normalized.isBlank()) {
        includes.add(normalized);
      }
      if (separator < 0) {
        break;
      }
      start = separator + 1;
    }
    return includes;
  }

  static Set<String> normalize(Set<String> includes) {
    return includes == null ? Set.of() : includes;
  }
}
