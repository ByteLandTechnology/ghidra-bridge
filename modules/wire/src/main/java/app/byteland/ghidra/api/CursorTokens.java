package app.byteland.ghidra.api;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class CursorTokens {
  private static final int CURSOR_PART_COUNT = 5;
  private static final int SIGNING_KEY_LENGTH = 32;
  private static final String DOMAIN = "ghidra-bridge-cursor-v2";
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
    try {
      String wire = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
      String[] parts = wire.split("\\n", -1);
      if (parts.length != CURSOR_PART_COUNT) {
        throw new IllegalArgumentException("invalid cursor parts");
      }
      String payload = parts[0] + "\n" + parts[1] + "\n" + parts[2] + "\n" + parts[3];
      if (!MessageDigest.isEqual(
          signature(payload).getBytes(StandardCharsets.US_ASCII),
          parts[4].getBytes(StandardCharsets.US_ASCII))) {
        throw new IllegalArgumentException("invalid cursor signature");
      }
      if (!parts[0].equals(resource) || !parts[1].equals(sessionId)) {
        throw new IllegalArgumentException("cursor belongs to another resource or session");
      }
      if (!parts[2].equals(queryFingerprint)) {
        throw new IllegalArgumentException("cursor belongs to another query");
      }
      return parts[3];
    } catch (IllegalArgumentException error) {
      ApiException translated =
          ApiException.badRequest("invalid_cursor", "cursor is invalid", target);
      translated.initCause(error);
      throw translated;
    }
  }

  public static String queryFingerprint(Map<String, Object> request) {
    Map<String, Object> query = new TreeMap<>();
    for (Map.Entry<String, Object> entry : request.entrySet()) {
      if (java.util.Set.of("cursor", "fields", "limit", "timeout_ms").contains(entry.getKey())) {
        continue;
      }
      if ("filter".equals(entry.getKey())
          && entry.getValue() instanceof Map<?, ?> filter
          && filter.isEmpty()) continue;
      query.put(entry.getKey(), canonical(entry.getValue()));
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

  private static Object canonical(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        sorted.put(String.valueOf(entry.getKey()), canonical(entry.getValue()));
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
