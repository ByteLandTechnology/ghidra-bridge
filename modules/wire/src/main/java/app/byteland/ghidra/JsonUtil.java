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
   * Serializes a Java map, list, string, number, boolean, or {@code null} to compact JSON text.
   *
   * @param value JSON-compatible Java value
   * @return compact JSON string
   */
  public static String toJson(Object value) {
    return JsonWriter.toJson(value);
  }

  /**
   * Wraps pre-serialized JSON text so {@link #toJson(Object)} emits it verbatim.
   *
   * @param json valid pre-serialized JSON fragment
   * @return opaque marker value recognized by the JSON writer
   */
  public static Object rawJson(String json) {
    return new JsonWriter.RawJson(Objects.requireNonNull(json, "json"));
  }

  /**
   * Parses a complete JSON value from {@code json}.
   *
   * @param json JSON input string
   * @return parsed Java value ({@code Map}, {@code List}, {@code String}, {@code Number}, {@code
   *     Boolean}, or {@code null})
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
   * Parses {@code json} and requires the top-level value to be a JSON object.
   *
   * @param json JSON object string
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
