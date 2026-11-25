package app.byteland.ghidra;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Serializes objects to compact JSON and parses JSON text.
 */
public final class JsonUtil {
  private JsonUtil() {}

  /**
   * Serializes {@code value} into a compact JSON string.
   *
   * @param value JSON-compatible object graph, or {@code null}
   * @return compact JSON representation
   */
  public static String toJson(Object value) {
    return JsonWriter.toJson(value);
  }

  /**
   * Wraps pre-serialized JSON text so {@link #toJson(Object)} writes it verbatim.
   *
   * @param json valid pre-serialized JSON fragment
   * @return raw JSON marker object
   */
  public static Object rawJson(String json) {
    return new JsonWriter.RawJson(Objects.requireNonNull(json, "json"));
  }

  /**
   * Parses a complete JSON document into Java maps, lists, strings, numbers, booleans, or {@code null}.
   *
   * @param json UTF-8 JSON document text
   * @return decoded Java value
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
   * Parses a JSON document and requires the root value to be a JSON object.
   *
   * @param json UTF-8 JSON object text
   * @return ordered map of object properties
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
