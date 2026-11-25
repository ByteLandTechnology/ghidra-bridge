package app.byteland.ghidra.api;

import java.util.Map;

/**
 * Decodes and encodes JSON values for API methods and publishes their schemas.
 *
 * @param <T> decoded object type
 */
public interface JsonCodec<T> {
  /**
   * Validates and converts a raw JSON value into {@code T}.
   *
   * @param value decoded JSON value
   * @param target JSON Pointer prefix for validation failures
   * @return validated typed value
   */
  T decode(Object value, String target);

  /**
   * Converts a typed value into JSON-serializable primitives, lists, and maps.
   *
   * @param value typed value to encode
   * @return JSON-serializable representation
   */
  Object encode(T value);

  /**
   * Returns the JSON Schema describing wire values accepted or produced by this codec.
   *
   * @return JSON Schema map
   */
  Map<String, Object> schema();
}
