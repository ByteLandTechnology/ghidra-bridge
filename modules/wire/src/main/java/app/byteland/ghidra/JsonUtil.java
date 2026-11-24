package app.byteland.ghidra;

import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serializes objects to compact JSON and parses JSON text.
 */
public final class JsonUtil {
  public static final int DEFAULT_MAX_UTF8_BYTES = JsonWriter.DEFAULT_MAX_UTF8_BYTES;

  private JsonUtil() {}

  public static String toJson(Object value) {
    return JsonWriter.toJson(value);
  }

  public static String toJson(Object value, int maxUtf8Bytes) {
    return JsonWriter.toJson(value, maxUtf8Bytes);
  }

  public static int utf8ByteLength(Object value, int maxUtf8Bytes) {
    return JsonWriter.utf8ByteLength(value, maxUtf8Bytes);
  }

  public static void writeUtf8(Object value, OutputStream output, int maxUtf8Bytes)
      throws IOException {
    JsonWriter.writeUtf8(value, output, maxUtf8Bytes);
  }

  public static Object parse(String json) {
    JsonParser parser = new JsonParser(json);
    Object value = parser.parseValue();
    parser.skipWhitespace();
    if (!parser.isAtEnd()) {
      throw new IllegalArgumentException(
          "Unexpected trailing content at index " + parser.currentIndex());
    }
    return value;
  }

  public static Map<String, Object> parseObject(String json) {
    Object parsed = parse(json);
    if (!(parsed instanceof Map<?, ?> map)) {
      throw new IllegalArgumentException("Expected JSON object");
    }
    Map<String, Object> object = new LinkedHashMap<>(map.size());
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw new IllegalArgumentException("Expected JSON object field name");
      }
      object.put(key, entry.getValue());
    }
    return object;
  }
}
