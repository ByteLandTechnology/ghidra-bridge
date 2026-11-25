package app.byteland.ghidra.api;

import java.util.Map;

/**
 * Decodes and encodes JSON values for API methods and publishes their schemas.
 *
 * @param <T> decoded object type
 */
public interface JsonCodec<T> {
  /**
   * Validates and decodes a JSON value into {@code T}.
   *
   * @param value raw decoded JSON value
   * @param target base JSON Pointer prefix for validation errors
   * @return decoded typed value
   */
  T decode(Object value, String target);

  /**
   * Encodes {@code value} into a JSON-serializable representation.
   *
   * @param value typed value to encode
   * @return JSON-serializable object
   */
  Object encode(T value);

  /**
   * Returns the JSON Schema describing wire values accepted or produced by this codec.
   *
   * @return JSON Schema map
   */
  Map<String, Object> schema();
}
