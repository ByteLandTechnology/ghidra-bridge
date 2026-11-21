package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Serializes objects to compact JSON and parses JSON text.
 */
public final class JsonUtil {
  private JsonUtil() {}

  /**
   * Serializes a JSON-compatible Java value into a compact JSON string.
   *
   * @param value JSON-compatible map, list, string, number, boolean, or null
   * @return serialized JSON text
   */
  public static String toJson(Object value) {
    return JsonWriter.toJson(value);
  }

  /**
   * Parses a JSON text document into Java maps, lists, strings, numbers, booleans, or null.
   *
   * @param json JSON document text
   * @return parsed Java value
   */
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

  /**
   * Parses a JSON text document and requires the root value to be a JSON object.
   *
   * @param json JSON object text
   * @return parsed string-keyed map
   */
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
