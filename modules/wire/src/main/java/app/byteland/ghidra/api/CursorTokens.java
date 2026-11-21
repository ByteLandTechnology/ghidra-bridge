package app.byteland.ghidra.api;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class CursorTokens {
  private static final int CURSOR_PART_COUNT = 5;
  private static final int SIGNING_KEY_LENGTH = 32;
  private static final String DOMAIN = "ghidra-bridge-cursor-v2";
  private static final Set<String> IGNORED_QUERY_KEYS =
      Set.of("cursor", "fields", "limit", "timeout_ms", "page", "projection");
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final byte[] SIGNING_KEY = generateSigningKey();

  private CursorTokens() {}

  public static String encode(
      String resource, String sessionId, String queryFingerprint, String compositeKey) {
    String payload =
        component(resource)
            + "\n"
            + component(sessionId)
            + "\n"
            + component(queryFingerprint)
            + "\n"
            + component(compositeKey);
    String wire = payload + "\n" + signature(payload);
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(wire.getBytes(StandardCharsets.UTF_8));
  }

  public static String decode(
      String token, String resource, String sessionId, String queryFingerprint, String target) {
    if (token == null) return null;
    String wire;
    try {
      byte[] decoded = Base64.getUrlDecoder().decode(token);
      wire = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(decoded)).toString();
    } catch (IllegalArgumentException | CharacterCodingException error) {
      ApiException translated =
          ApiException.badRequest(
              "invalid_cursor",
              "Cursor is not valid Base64URL-encoded UTF-8 text.",
              target);
      translated.initCause(error);
      throw translated;
    }
    String[] parts = wire.split("\\n", -1);
    if (parts.length != CURSOR_PART_COUNT) {
      throw ApiException.badRequest(
          "invalid_cursor",
          "Cursor token format is malformed and could not be parsed.",
          target);
    }
    String payload = parts[0] + "\n" + parts[1] + "\n" + parts[2] + "\n" + parts[3];
    if (!MessageDigest.isEqual(
        signature(payload).getBytes(StandardCharsets.US_ASCII),
        parts[4].getBytes(StandardCharsets.US_ASCII))) {
      throw ApiException.badRequest(
          "invalid_cursor",
          "Cursor signature is invalid or came from a previous server instance.",
          target);
    }
    if (!parts[0].equals(resource)) {
      throw ApiException.badRequest(
          "invalid_cursor",
          "Cursor belongs to \"" + parts[0] + "\" and cannot be used with \"" + resource + "\".",
          target);
    }
    if (!parts[1].equals(sessionId)) {
      throw ApiException.badRequest(
          "invalid_cursor",
          "Cursor belongs to a different Ghidra session (\"" + parts[1]
              + "\"); start pagination from the first page in the active session (\""
              + sessionId + "\").",
          target);
    }
    if (!parts[2].equals(queryFingerprint)) {
      throw ApiException.badRequest(
          "invalid_cursor",
          "Cursor cannot be reused because the query filter or scan range changed since the"
              + " previous page.",
          target);
    }
    return parts[3];
  }

  public static String queryFingerprint(Map<String, Object> request) {
    Map<String, Object> query = new TreeMap<>();
    for (Map.Entry<String, Object> entry : request.entrySet()) {
      String key = entry.getKey();
      if (IGNORED_QUERY_KEYS.contains(key)) {
        continue;
      }
      if ("scan".equals(key) && entry.getValue() instanceof Map<?, ?> scanMap) {
        if (!request.containsKey("range") && scanMap.containsKey("range")) {
          putIfNonEmptyMap(query, "range", canonical(scanMap.get("range")));
        }
        continue;
      }
      putIfNonEmptyMap(query, key, canonical(entry.getValue()));
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              digest.digest(
                  app.byteland.ghidra.JsonUtil.toJson(query).getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private static void putIfNonEmptyMap(Map<String, Object> target, String key, Object normalized) {
    if (normalized instanceof Map<?, ?> map && map.isEmpty()) {
      return;
    }
    target.put(key, normalized);
  }

  private static Object canonical(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        Object normalized = canonical(entry.getValue());
        if (normalized instanceof Map<?, ?> nestedMap && nestedMap.isEmpty()) {
          continue;
        }
        sorted.put(String.valueOf(entry.getKey()), normalized);
      }
      return new LinkedHashMap<>(sorted);
    }
    if (value instanceof Iterable<?> iterable) {
      List<Object> result = new ArrayList<>();
      for (Object item : iterable) result.add(canonical(item));
      return result;
    }
    return value;
  }

  private static String signature(String payload) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(SIGNING_KEY, "HmacSHA256"));
      byte[] bytes = mac.doFinal((DOMAIN + "\n" + payload).getBytes(StandardCharsets.UTF_8));
      return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    } catch (java.security.GeneralSecurityException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  static byte[] generateSigningKey() {
    byte[] key = new byte[SIGNING_KEY_LENGTH];
    SECURE_RANDOM.nextBytes(key);
    return key;
  }

  private static String component(String value) {
    if (value == null || value.contains("\n")) {
      throw new IllegalArgumentException("cursor components must be non-null single-line strings");
    }
    return value;
  }
}
