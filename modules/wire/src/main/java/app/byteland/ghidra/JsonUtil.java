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
   * Serializes a JSON-compatible value to compact JSON text.
   *
   * @param value map, list, string, number, boolean, or {@code null}
   * @return compact JSON string
   */
  public static String toJson(Object value) {
    return JsonWriter.toJson(value);
  }

  /**
   * Wraps pre-serialized JSON text so {@link #toJson(Object)} writes it verbatim.
   *
   * @param json valid pre-serialized JSON fragment
   * @return raw JSON marker value
   */
  public static Object rawJson(String json) {
    return new JsonWriter.RawJson(Objects.requireNonNull(json, "json"));
  }

  /**
   * Parses a JSON text document into Java values.
   *
   * @param json JSON text to parse
   * @return parsed JSON value
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
   * Parses a JSON text document and requires the root value to be an object.
   *
   * @param json JSON object text
   * @return ordered map of object fields
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
