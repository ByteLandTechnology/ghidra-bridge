package app.byteland.ghidra.api;

import java.util.Map;

/**
 * Decodes and encodes JSON values for API methods and publishes their schemas.
 *
 * @param <T> decoded object type
 */
public interface JsonCodec<T> {
  T decode(Object value, String target);

  Object encode(T value);

  Map<String, Object> schema();
}
