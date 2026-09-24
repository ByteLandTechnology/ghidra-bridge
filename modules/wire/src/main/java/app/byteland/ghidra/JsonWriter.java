package app.byteland.ghidra;

import java.lang.reflect.Array;
import java.util.Locale;
import java.util.Map;

final class JsonWriter {
  private static final int MAX_NESTING_DEPTH = 500;

  private static final char FIRST_NON_CONTROL_CHARACTER = 0x20;

  private JsonWriter() {}

  static String toJson(Object value) {
    StringBuilder builder = new StringBuilder();
    writeJson(builder, value, 0);
    return builder.toString();
  }

  private static void writeJson(StringBuilder builder, Object value, int depth) {
    if (value == null) {
      builder.append("null");
      return;
    }
    if (value instanceof String string) {
      builder.append('"').append(escape(string)).append('"');
      return;
    }
    if (value instanceof Number number) {
      if (number instanceof Double || number instanceof Float) {
        double asDouble = number.doubleValue();
        builder.append(Double.isFinite(asDouble) ? number : "null");
      } else {
        builder.append(number);
      }
      return;
    }
    if (value instanceof Boolean bool) {
      builder.append(bool);
      return;
    }
    if (value instanceof Map<?, ?> map) {
      int nextDepth = enterNesting(depth);
      builder.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (!(entry.getKey() instanceof String key)) {
          throw new IllegalArgumentException("JSON object keys must be strings");
        }
        if (!first) {
          builder.append(',');
        }
        first = false;
        builder.append('"').append(escape(key)).append("\":");
        writeJson(builder, entry.getValue(), nextDepth);
      }
      builder.append('}');
      return;
    }
    if (value instanceof Iterable<?> iterable) {
      int nextDepth = enterNesting(depth);
      builder.append('[');
      boolean first = true;
      for (Object item : iterable) {
        if (!first) {
          builder.append(',');
        }
        first = false;
        writeJson(builder, item, nextDepth);
      }
      builder.append(']');
      return;
    }
    if (value.getClass().isArray()) {
      int nextDepth = enterNesting(depth);
      builder.append('[');
      int length = Array.getLength(value);
      for (int i = 0; i < length; i++) {
        if (i > 0) {
          builder.append(',');
        }
        writeJson(builder, Array.get(value, i), nextDepth);
      }
      builder.append(']');
      return;
    }
    builder.append('"').append(escape(String.valueOf(value))).append('"');
  }

  private static int enterNesting(int depth) {
    int nextDepth = depth + 1;
    if (nextDepth > MAX_NESTING_DEPTH) {
      throw new IllegalArgumentException(
          "JSON nesting exceeds maximum depth of " + MAX_NESTING_DEPTH);
    }
    return nextDepth;
  }

  private static String escape(String value) {
    StringBuilder escaped = new StringBuilder(value.length() + 8);
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> escaped.append("\\\"");
        case '\\' -> escaped.append("\\\\");
        case '\b' -> escaped.append("\\b");
        case '\f' -> escaped.append("\\f");
        case '\n' -> escaped.append("\\n");
        case '\r' -> escaped.append("\\r");
        case '\t' -> escaped.append("\\t");
        default -> {
          if (ch < FIRST_NON_CONTROL_CHARACTER) {
            escaped.append(String.format(Locale.ROOT, "\\u%04x", (int) ch));
          } else {
            escaped.append(ch);
          }
        }
      }
    }
    return escaped.toString();
  }
}
