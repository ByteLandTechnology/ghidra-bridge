package app.byteland.ghidra.api;

import app.byteland.ghidra.JsonUtil;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
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
    if (token.isBlank()) {
      throw invalidCursor(
          "Cursor token is malformed. Omit page.cursor to start from the first page.",
          target,
          "malformed_token",
          null);
    }
    String wire;
    try {
      wire = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException error) {
      throw invalidCursor(
          "Cursor token is malformed. Omit page.cursor to start from the first page.",
          target,
          "malformed_token",
          error);
    }
    String[] parts = wire.split("\\n", -1);
    if (parts.length != CURSOR_PART_COUNT || parts[3].isEmpty() || parts[4].isEmpty()) {
      throw invalidCursor(
          "Cursor token is malformed. Omit page.cursor to start from the first page.",
          target,
          "malformed_token",
          null);
    }
    String payload = parts[0] + "\n" + parts[1] + "\n" + parts[2] + "\n" + parts[3];
    if (!MessageDigest.isEqual(
        signature(payload).getBytes(StandardCharsets.US_ASCII),
        parts[4].getBytes(StandardCharsets.US_ASCII))) {
      throw invalidCursor(
          "Cursor token signature is invalid. Omit page.cursor to start a new pagination sequence.",
          target,
          "invalid_signature",
          null);
    }
    if (!parts[1].equals(sessionId)) {
      throw invalidCursor(
          "Cursor token belongs to a different session. Omit page.cursor to start pagination in the"
              + " current session.",
          target,
          "session_mismatch",
          null);
    }
    if (!parts[0].equals(resource)) {
      throw invalidCursor(
          "Cursor token belongs to a different list operation. Omit page.cursor to start"
              + " pagination for this operation.",
          target,
          "resource_mismatch",
          null);
    }
    if (!parts[2].equals(queryFingerprint)) {
      throw invalidCursor(
          "Cursor token does not match the current filter or scan range. Keep filter and"
              + " scan.range unchanged while paging, or omit page.cursor to start a new query.",
          target,
          "filter_mismatch",
          null);
    }
    return parts[3];
  }

  private static ApiException invalidCursor(
      String message, String target, String reason, Throwable cause) {
    ApiException exception =
        new ApiException(
            400, new BridgeError(400, "invalid_cursor", message, target, Map.of("reason", reason)));
    if (cause != null) {
      exception.initCause(cause);
    }
    return exception;
  }

  public static String queryFingerprint(Map<String, Object> request) {
    Map<String, Object> query = new TreeMap<>();
    for (Map.Entry<String, Object> entry : request.entrySet()) {
      if (java.util.Set.of("cursor", "fields", "limit", "timeout_ms").contains(entry.getKey())) {
        continue;
      }
      Object pruned = pruneEmptyMaps(entry.getValue());
      if (pruned instanceof Map<?, ?> map && map.isEmpty()) {
        continue;
      }
      query.put(entry.getKey(), JsonUtil.canonical(pruned));
    }
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(digest.digest(JsonUtil.toJson(query).getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.GeneralSecurityException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  private static Object pruneEmptyMaps(Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      return value;
    }
    Map<String, Object> pruned = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      Object child = pruneEmptyMaps(entry.getValue());
      if (child instanceof Map<?, ?> childMap && childMap.isEmpty()) {
        continue;
      }
      pruned.put(String.valueOf(entry.getKey()), child);
    }
    return pruned;
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
