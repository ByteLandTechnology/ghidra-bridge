package app.byteland.ghidra.api;

import java.util.Map;

/**
 * Decodes and encodes JSON values for API methods and publishes their schemas.
 *
 * @param <T> decoded object type
 */
public interface JsonCodec<T> {
  /**
   * Validates and decodes a raw JSON value into {@code T}.
   *
   * @param value parsed JSON value
   * @param target JSON pointer prefix for validation errors
   * @return decoded value
   */
  T decode(Object value, String target);

  /**
   * Encodes a typed value into JSON-compatible primitives, lists, and maps.
   *
   * @param value typed value to encode
   * @return JSON-compatible representation
   */
  Object encode(T value);

  /**
   * Returns the JSON Schema map that describes valid wire values for this codec.
   *
   * @return JSON Schema map
   */
  Map<String, Object> schema();
}
