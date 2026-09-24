package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serializes objects to compact JSON and parses JSON text.
 */
public final class JsonUtil {
  private JsonUtil() {}

  public static String toJson(Object value) {
    return JsonWriter.toJson(value);
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
