package app.byteland.ghidra;

import app.byteland.ghidra.api.ApiException;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.RandomAccess;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

final class JsonWriter {
  static final int DEFAULT_MAX_UTF8_BYTES = 16 * 1024 * 1024;

  private static final int MAX_NESTING_DEPTH = 500;
  private static final int MAX_ESTIMATE_DEPTH = 6;
  private static final int MAX_COLLECTION_SAMPLE = 16;
  private static final int MIN_INITIAL_CAPACITY = 16;
  private static final int MAX_INITIAL_CAPACITY = DEFAULT_MAX_UTF8_BYTES;
  private static final int STREAM_BUFFER_SIZE = 8192;
  private static final char FIRST_NON_CONTROL_CHARACTER = 0x20;
  private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

  private JsonWriter() {}

  static final class RawJson {
    private final String json;

    RawJson(String json) {
      this.json = Objects.requireNonNull(json, "json");
    }

    String json() {
      return json;
    }

    @Override
    public boolean equals(Object other) {
      return this == other || (other instanceof RawJson that && json.equals(that.json));
    }

    @Override
    public int hashCode() {
      return json.hashCode();
    }

    @Override
    public String toString() {
      return json;
    }
  }

  static String toJson(Object value) {
    return toJson(value, DEFAULT_MAX_UTF8_BYTES);
  }

  static String toJson(Object value, int maxUtf8Bytes) {
    requireNonNegativeLimit(maxUtf8Bytes);
    if (value instanceof RawJson raw) {
      utf8ByteLength(raw, maxUtf8Bytes);
      return raw.json();
    }
    int initialCapacity = Math.min(estimateInitialCapacity(value), maxUtf8Bytes);
    StringSink sink = new StringSink(maxUtf8Bytes, initialCapacity);
    try {
      writeJson(sink, value, 0);
    } catch (IOException impossible) {
      throw new AssertionError(impossible);
    }
    return sink.finish();
  }

  static int utf8ByteLength(Object value, int maxUtf8Bytes) {
    requireNonNegativeLimit(maxUtf8Bytes);
    CountingSink sink = new CountingSink(maxUtf8Bytes);
    try {
      writeJson(sink, value, 0);
    } catch (IOException impossible) {
      throw new AssertionError(impossible);
    }
    return sink.utf8Bytes();
  }

  static void writeUtf8(Object value, OutputStream output, int maxUtf8Bytes) throws IOException {
    Objects.requireNonNull(output, "output");
    requireNonNegativeLimit(maxUtf8Bytes);
    Utf8StreamSink sink = new Utf8StreamSink(output, maxUtf8Bytes);
    writeJson(sink, value, 0);
    sink.flush();
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
    if (value instanceof RawJson raw) {
      return Math.min(MAX_INITIAL_CAPACITY, raw.json().length());
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
      if (!isEstimableMap(map)) {
        return 64;
      }
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
      if (!isEstimableCollection(collection)) {
        return 64;
      }
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
          sampleCount < length
              ? (sampleTotal * length + sampleCount - 1) / sampleCount
              : sampleTotal;
      return Math.min(MAX_INITIAL_CAPACITY, 2 + itemsEstimate + (length - 1));
    }
    if (value.getClass().isArray()) {
      int length = Array.getLength(value);
      return length == 0 ? 2 : Math.min(MAX_INITIAL_CAPACITY, 2 + (long) length * 8);
    }
    return MIN_INITIAL_CAPACITY;
  }

  private static boolean isEstimableMap(Map<?, ?> map) {
    if (map instanceof HashMap<?, ?>
        || map instanceof TreeMap<?, ?>
        || map instanceof ConcurrentHashMap<?, ?>) {
      return true;
    }
    String className = map.getClass().getName();
    return className.startsWith("java.util.ImmutableCollections$")
        || className.equals("java.util.Collections$SingletonMap")
        || className.equals("java.util.Collections$EmptyMap");
  }

  private static boolean isEstimableCollection(Collection<?> collection) {
    if (collection instanceof ArrayList<?>
        || collection instanceof HashSet<?>
        || collection instanceof TreeSet<?>
        || collection instanceof ArrayDeque<?>) {
      return true;
    }
    String className = collection.getClass().getName();
    return className.startsWith("java.util.ImmutableCollections$")
        || className.equals("java.util.Arrays$ArrayList")
        || className.equals("java.util.Collections$SingletonList")
        || className.equals("java.util.Collections$EmptyList")
        || className.equals("java.util.Collections$SingletonSet")
        || className.equals("java.util.Collections$EmptySet");
  }

  private static void requireNonNegativeLimit(int maxUtf8Bytes) {
    if (maxUtf8Bytes < 0) {
      throw new IllegalArgumentException("maxUtf8Bytes must not be negative");
    }
  }

  private static ApiException tooLarge(int maxUtf8Bytes) {
    return new ApiException(
        413,
        "response_too_large",
        "serialized JSON exceeds maximum size of " + maxUtf8Bytes + " bytes",
        null);
  }

  private static void writeJson(JsonSink sink, Object value, int depth) throws IOException {
    if (value == null) {
      sink.writeAscii("null");
      return;
    }
    if (value instanceof RawJson raw) {
      writeRawJson(sink, raw.json());
      return;
    }
    if (value instanceof String string) {
      writeQuotedString(sink, string);
      return;
    }
    if (value instanceof Number number) {
      if (number instanceof Double || number instanceof Float) {
        double asDouble = number.doubleValue();
        sink.writeAscii(Double.isFinite(asDouble) ? number.toString() : "null");
      } else {
        sink.writeAscii(number.toString());
      }
      return;
    }
    if (value instanceof Boolean bool) {
      sink.writeAscii(bool.booleanValue() ? "true" : "false");
      return;
    }
    if (value instanceof Map<?, ?> map) {
      int nextDepth = enterNesting(depth);
      sink.writeAsciiChar('{');
      boolean first = true;
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (!(entry.getKey() instanceof String key)) {
          throw new IllegalArgumentException("JSON object keys must be strings");
        }
        if (!first) {
          sink.writeAsciiChar(',');
        }
        first = false;
        writeQuotedString(sink, key);
        sink.writeAsciiChar(':');
        writeJson(sink, entry.getValue(), nextDepth);
      }
      sink.writeAsciiChar('}');
      return;
    }
    if (value instanceof Iterable<?> iterable) {
      int nextDepth = enterNesting(depth);
      sink.writeAsciiChar('[');
      if (iterable instanceof List<?> list && list instanceof RandomAccess) {
        for (int i = 0, size = list.size(); i < size; i++) {
          if (i > 0) {
            sink.writeAsciiChar(',');
          }
          writeJson(sink, list.get(i), nextDepth);
        }
      } else {
        boolean first = true;
        for (Object item : iterable) {
          if (!first) {
            sink.writeAsciiChar(',');
          }
          first = false;
          writeJson(sink, item, nextDepth);
        }
      }
      sink.writeAsciiChar(']');
      return;
    }
    if (value.getClass().isArray()) {
      int nextDepth = enterNesting(depth);
      sink.writeAsciiChar('[');
      int length = Array.getLength(value);
      for (int i = 0; i < length; i++) {
        if (i > 0) {
          sink.writeAsciiChar(',');
        }
        writeJson(sink, Array.get(value, i), nextDepth);
      }
      sink.writeAsciiChar(']');
      return;
    }
    writeQuotedString(sink, String.valueOf(value));
  }

  private static int enterNesting(int depth) {
    int nextDepth = depth + 1;
    if (nextDepth > MAX_NESTING_DEPTH) {
      throw new IllegalArgumentException(
          "JSON nesting exceeds maximum depth of " + MAX_NESTING_DEPTH);
    }
    return nextDepth;
  }

  private static void writeRawJson(JsonSink sink, String value) throws IOException {
    int length = value.length();
    int asciiStart = 0;
    for (int i = 0; i < length; i++) {
      char ch = value.charAt(i);
      if (ch < 0x80) {
        continue;
      }
      if (i > asciiStart) {
        sink.writeAsciiSlice(value, asciiStart, i);
      }
      if (Character.isHighSurrogate(ch)
          && i + 1 < length
          && Character.isLowSurrogate(value.charAt(i + 1))) {
        sink.writeSurrogatePair(ch, value.charAt(++i));
      } else if (Character.isSurrogate(ch)) {
        sink.writeUnpairedSurrogate(ch);
      } else {
        sink.writeBmpNonAscii(ch);
      }
      asciiStart = i + 1;
    }
    if (asciiStart < length) {
      sink.writeAsciiSlice(value, asciiStart, length);
    }
  }

  private static void writeQuotedString(JsonSink sink, String value) throws IOException {
    sink.writeAsciiChar('"');
    int length = value.length();
    int asciiStart = 0;
    for (int i = 0; i < length; i++) {
      char ch = value.charAt(i);
      if (ch >= FIRST_NON_CONTROL_CHARACTER && ch < 0x80 && ch != '"' && ch != '\\') {
        continue;
      }
      if (i > asciiStart) {
        sink.writeAsciiSlice(value, asciiStart, i);
      }
      switch (ch) {
        case '"' -> sink.writeAscii("\\\"");
        case '\\' -> sink.writeAscii("\\\\");
        case '\b' -> sink.writeAscii("\\b");
        case '\f' -> sink.writeAscii("\\f");
        case '\n' -> sink.writeAscii("\\n");
        case '\r' -> sink.writeAscii("\\r");
        case '\t' -> sink.writeAscii("\\t");
        default -> {
          if (ch < FIRST_NON_CONTROL_CHARACTER) {
            sink.writeControlEscape(ch);
          } else if (Character.isHighSurrogate(ch)
              && i + 1 < length
              && Character.isLowSurrogate(value.charAt(i + 1))) {
            sink.writeSurrogatePair(ch, value.charAt(++i));
          } else if (Character.isSurrogate(ch)) {
            sink.writeUnpairedSurrogate(ch);
          } else {
            sink.writeBmpNonAscii(ch);
          }
        }
      }
      asciiStart = i + 1;
    }
    if (asciiStart < length) {
      sink.writeAsciiSlice(value, asciiStart, length);
    }
    sink.writeAsciiChar('"');
  }

  private interface JsonSink {
    void writeAsciiChar(char ch) throws IOException;

    void writeAscii(String ascii) throws IOException;

    void writeAsciiSlice(String value, int start, int end) throws IOException;

    void writeControlEscape(char ch) throws IOException;

    void writeBmpNonAscii(char ch) throws IOException;

    void writeSurrogatePair(char high, char low) throws IOException;

    void writeUnpairedSurrogate(char ch) throws IOException;
  }

  private abstract static class BoundedSink implements JsonSink {
    private final int maxUtf8Bytes;
    private int utf8Bytes;

    BoundedSink(int maxUtf8Bytes) {
      this.maxUtf8Bytes = maxUtf8Bytes;
    }

    final void charge(int byteCount) {
      if (byteCount > maxUtf8Bytes - utf8Bytes) {
        throw tooLarge(maxUtf8Bytes);
      }
      utf8Bytes += byteCount;
    }

    final int utf8Bytes() {
      return utf8Bytes;
    }
  }

  private static final class CountingSink extends BoundedSink {
    CountingSink(int maxUtf8Bytes) {
      super(maxUtf8Bytes);
    }

    @Override
    public void writeAsciiChar(char ch) {
      charge(1);
    }

    @Override
    public void writeAscii(String ascii) {
      charge(ascii.length());
    }

    @Override
    public void writeAsciiSlice(String value, int start, int end) {
      charge(end - start);
    }

    @Override
    public void writeControlEscape(char ch) {
      charge(6);
    }

    @Override
    public void writeBmpNonAscii(char ch) {
      charge(ch < 0x800 ? 2 : 3);
    }

    @Override
    public void writeSurrogatePair(char high, char low) {
      charge(4);
    }

    @Override
    public void writeUnpairedSurrogate(char ch) {
      charge(1);
    }
  }

  private static final class StringSink extends BoundedSink {
    private final StringBuilder builder;

    StringSink(int maxUtf8Bytes, int initialCapacity) {
      super(maxUtf8Bytes);
      this.builder = new StringBuilder(initialCapacity);
    }

    @Override
    public void writeAsciiChar(char ch) {
      charge(1);
      builder.append(ch);
    }

    @Override
    public void writeAscii(String ascii) {
      charge(ascii.length());
      builder.append(ascii);
    }

    @Override
    public void writeAsciiSlice(String value, int start, int end) {
      charge(end - start);
      builder.append(value, start, end);
    }

    @Override
    public void writeControlEscape(char ch) {
      charge(6);
      builder
          .append('\\')
          .append('u')
          .append('0')
          .append('0')
          .append(HEX_DIGITS[(ch >>> 4) & 0xF])
          .append(HEX_DIGITS[ch & 0xF]);
    }

    @Override
    public void writeBmpNonAscii(char ch) {
      charge(ch < 0x800 ? 2 : 3);
      builder.append(ch);
    }

    @Override
    public void writeSurrogatePair(char high, char low) {
      charge(4);
      builder.append(high).append(low);
    }

    @Override
    public void writeUnpairedSurrogate(char ch) {
      charge(1);
      builder.append(ch);
    }

    String finish() {
      return builder.toString();
    }
  }

  private static final class Utf8StreamSink extends BoundedSink {
    private final OutputStream output;
    private final byte[] buffer = new byte[STREAM_BUFFER_SIZE];
    private int position;

    Utf8StreamSink(OutputStream output, int maxUtf8Bytes) {
      super(maxUtf8Bytes);
      this.output = output;
    }

    @Override
    public void writeAsciiChar(char ch) throws IOException {
      charge(1);
      ensureRoom(1);
      buffer[position++] = (byte) ch;
    }

    @Override
    public void writeAscii(String ascii) throws IOException {
      writeAsciiSlice(ascii, 0, ascii.length());
    }

    @Override
    public void writeAsciiSlice(String value, int start, int end) throws IOException {
      charge(end - start);
      int index = start;
      while (index < end) {
        if (position == buffer.length) {
          flush();
        }
        int chunk = Math.min(end - index, buffer.length - position);
        for (int i = 0; i < chunk; i++) {
          buffer[position++] = (byte) value.charAt(index++);
        }
      }
    }

    @Override
    public void writeControlEscape(char ch) throws IOException {
      charge(6);
      ensureRoom(6);
      buffer[position++] = '\\';
      buffer[position++] = 'u';
      buffer[position++] = '0';
      buffer[position++] = '0';
      buffer[position++] = (byte) HEX_DIGITS[(ch >>> 4) & 0xF];
      buffer[position++] = (byte) HEX_DIGITS[ch & 0xF];
    }

    @Override
    public void writeBmpNonAscii(char ch) throws IOException {
      if (ch < 0x800) {
        charge(2);
        ensureRoom(2);
        buffer[position++] = (byte) (0xC0 | (ch >>> 6));
        buffer[position++] = (byte) (0x80 | (ch & 0x3F));
      } else {
        charge(3);
        ensureRoom(3);
        buffer[position++] = (byte) (0xE0 | (ch >>> 12));
        buffer[position++] = (byte) (0x80 | ((ch >>> 6) & 0x3F));
        buffer[position++] = (byte) (0x80 | (ch & 0x3F));
      }
    }

    @Override
    public void writeSurrogatePair(char high, char low) throws IOException {
      charge(4);
      ensureRoom(4);
      int codePoint = Character.toCodePoint(high, low);
      buffer[position++] = (byte) (0xF0 | (codePoint >>> 18));
      buffer[position++] = (byte) (0x80 | ((codePoint >>> 12) & 0x3F));
      buffer[position++] = (byte) (0x80 | ((codePoint >>> 6) & 0x3F));
      buffer[position++] = (byte) (0x80 | (codePoint & 0x3F));
    }

    @Override
    public void writeUnpairedSurrogate(char ch) throws IOException {
      charge(1);
      ensureRoom(1);
      buffer[position++] = '?';
    }

    void flush() throws IOException {
      if (position > 0) {
        output.write(buffer, 0, position);
        position = 0;
      }
    }

    private void ensureRoom(int needed) throws IOException {
      if (position + needed > buffer.length) {
        flush();
      }
    }
  }
}
