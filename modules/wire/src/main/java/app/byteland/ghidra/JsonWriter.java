package app.byteland.ghidra;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.RandomAccess;

final class JsonWriter {
  private static final int MAX_NESTING_DEPTH = 500;
  private static final int MAX_ESTIMATE_DEPTH = 6;
  private static final int MAX_COLLECTION_SAMPLE = 16;
  private static final int MIN_INITIAL_CAPACITY = 16;
  private static final int MAX_INITIAL_CAPACITY = 16 * 1024 * 1024;

  private static final char FIRST_NON_CONTROL_CHARACTER = 0x20;
  private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

  private JsonWriter() {}

  static String toJson(Object value) {
    StringBuilder builder = new StringBuilder(estimateInitialCapacity(value));
    writeJson(builder, value, 0);
    return builder.toString();
  }

  static int estimateInitialCapacity(Object value) {
    if (value == null || value instanceof Boolean || value instanceof Number) {
      return MIN_INITIAL_CAPACITY;
    }
    long estimated = estimateCapacity(value, 0);
    long withHeadroom = estimated + (estimated >>> 4) + 16;
    return Math.clamp(withHeadroom, MIN_INITIAL_CAPACITY, MAX_INITIAL_CAPACITY);
  }

  private static long estimateCapacity(Object value, int depth) {
    if (value == null) {
      return 4;
    }
    if (value instanceof String string) {
      return Math.min(MAX_INITIAL_CAPACITY, (long) string.length() + 2);
    }
    if (value instanceof Boolean bool) {
      return bool ? 4 : 5;
    }
    if (value instanceof Number) {
      return 12;
    }
    if (value instanceof Map<?, ?> map) {
      int size = map.size();
      if (size == 0) {
        return 2;
      }
      if (depth >= MAX_ESTIMATE_DEPTH) {
        return Math.min(MAX_INITIAL_CAPACITY, 2 + (long) size * 28);
      }
      int nextDepth = depth + 1;
      long sampleTotal = 0;
      int sampled = 0;
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        long keyLength = entry.getKey() instanceof String key ? (long) key.length() + 3 : 8;
        sampleTotal += keyLength + estimateCapacity(entry.getValue(), nextDepth);
        sampled++;
        if (sampled >= MAX_COLLECTION_SAMPLE) {
          break;
        }
      }
      long entriesEstimate =
          sampled < size ? (sampleTotal * size + sampled - 1) / sampled : sampleTotal;
      return Math.min(MAX_INITIAL_CAPACITY, 2 + entriesEstimate + (size - 1));
    }
    if (value instanceof Collection<?> collection) {
      int size = collection.size();
      if (size == 0) {
        return 2;
      }
      if (depth >= MAX_ESTIMATE_DEPTH) {
        return Math.min(MAX_INITIAL_CAPACITY, 2 + (long) size * 24);
      }
      int nextDepth = depth + 1;
      if (collection instanceof List<?> list && list instanceof RandomAccess) {
        if (size <= MAX_COLLECTION_SAMPLE) {
          long total = 0;
          for (int i = 0; i < size; i++) {
            total += estimateCapacity(list.get(i), nextDepth);
          }
          return Math.min(MAX_INITIAL_CAPACITY, 2 + total + (size - 1));
        }
        long sampleTotal = 0;
        for (int i = 0; i < MAX_COLLECTION_SAMPLE; i++) {
          int index = (int) ((long) i * (size - 1) / (MAX_COLLECTION_SAMPLE - 1));
          sampleTotal += estimateCapacity(list.get(index), nextDepth);
        }
        long itemsEstimate =
            (sampleTotal * size + MAX_COLLECTION_SAMPLE - 1) / MAX_COLLECTION_SAMPLE;
        return Math.min(MAX_INITIAL_CAPACITY, 2 + itemsEstimate + (size - 1));
      }
      long sampleTotal = 0;
      int sampled = 0;
      for (Object item : collection) {
        sampleTotal += estimateCapacity(item, nextDepth);
        sampled++;
        if (sampled >= MAX_COLLECTION_SAMPLE) {
          break;
        }
      }
      long itemsEstimate =
          sampled < size ? (sampleTotal * size + sampled - 1) / sampled : sampleTotal;
      return Math.min(MAX_INITIAL_CAPACITY, 2 + itemsEstimate + (size - 1));
    }
    if (value instanceof Object[] array) {
      int length = array.length;
      if (length == 0) {
        return 2;
      }
      if (depth >= MAX_ESTIMATE_DEPTH) {
        return Math.min(MAX_INITIAL_CAPACITY, 2 + (long) length * 24);
      }
      int nextDepth = depth + 1;
      int sampleCount = Math.min(length, MAX_COLLECTION_SAMPLE);
      long sampleTotal = 0;
      for (int i = 0; i < sampleCount; i++) {
        int index =
            sampleCount == length ? i : (int) ((long) i * (length - 1) / (sampleCount - 1));
        sampleTotal += estimateCapacity(array[index], nextDepth);
      }
      long itemsEstimate =
          sampleCount < length ? (sampleTotal * length + sampleCount - 1) / sampleCount : sampleTotal;
      return Math.min(MAX_INITIAL_CAPACITY, 2 + itemsEstimate + (length - 1));
    }
    if (value.getClass().isArray()) {
      int length = Array.getLength(value);
      return length == 0 ? 2 : Math.min(MAX_INITIAL_CAPACITY, 2 + (long) length * 8);
    }
    return MIN_INITIAL_CAPACITY;
  }

  private static void writeJson(StringBuilder builder, Object value, int depth) {
    if (value == null) {
      builder.append("null");
      return;
    }
    if (value instanceof String string) {
      writeQuotedString(builder, string);
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
        writeQuotedString(builder, key);
        builder.append(':');
        writeJson(builder, entry.getValue(), nextDepth);
      }
      builder.append('}');
      return;
    }
    if (value instanceof Iterable<?> iterable) {
      int nextDepth = enterNesting(depth);
      builder.append('[');
      if (iterable instanceof List<?> list && list instanceof RandomAccess) {
        for (int i = 0, size = list.size(); i < size; i++) {
          if (i > 0) {
            builder.append(',');
          }
          writeJson(builder, list.get(i), nextDepth);
        }
      } else {
        boolean first = true;
        for (Object item : iterable) {
          if (!first) {
            builder.append(',');
          }
          first = false;
          writeJson(builder, item, nextDepth);
        }
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
    writeQuotedString(builder, String.valueOf(value));
  }

  private static int enterNesting(int depth) {
    int nextDepth = depth + 1;
    if (nextDepth > MAX_NESTING_DEPTH) {
      throw new IllegalArgumentException(
          "JSON nesting exceeds maximum depth of " + MAX_NESTING_DEPTH);
    }
    return nextDepth;
  }

  private static void writeQuotedString(StringBuilder builder, String value) {
    builder.append('"');
    int length = value.length();
    int runStart = 0;
    for (int i = 0; i < length; i++) {
      char ch = value.charAt(i);
      if (ch >= FIRST_NON_CONTROL_CHARACTER && ch != '"' && ch != '\\') {
        continue;
      }
      if (i > runStart) {
        builder.append(value, runStart, i);
      }
      switch (ch) {
        case '"' -> builder.append("\\\"");
        case '\\' -> builder.append("\\\\");
        case '\b' -> builder.append("\\b");
        case '\f' -> builder.append("\\f");
        case '\n' -> builder.append("\\n");
        case '\r' -> builder.append("\\r");
        case '\t' -> builder.append("\\t");
        default ->
            builder
                .append("\\u00")
                .append(HEX_DIGITS[(ch >>> 4) & 0x0f])
                .append(HEX_DIGITS[ch & 0x0f]);
      }
      runStart = i + 1;
    }
    if (runStart < length) {
      builder.append(value, runStart, length);
    }
    builder.append('"');
  }
}
