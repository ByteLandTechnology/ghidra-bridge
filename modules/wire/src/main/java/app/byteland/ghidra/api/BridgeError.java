package app.byteland.ghidra.api;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Structured wire error payload shared across JSON-RPC and MCP transports.
 *
 * @param status HTTP-equivalent status code in {@code 400..599}
 * @param code snake_case machine-readable error code
 * @param message non-blank human-readable error summary
 * @param target optional JSON Pointer identifying the offending field, or {@code null}
 * @param details optional map of structured diagnostic fields
 */
public record BridgeError(
    int status, String code, String message, String target, Map<String, Object> details) {
  private static final Pattern CODE_PATTERN = Pattern.compile("[a-z][a-z0-9_]*");

  /**
   * Validates error status, code syntax, message, and defensively copies {@code details}.
   */
  public BridgeError {
    if (status < 400 || status > 599) {
      throw new IllegalArgumentException("bridge error status must be in 400..599");
    }
    if (code == null || !CODE_PATTERN.matcher(code).matches()) {
      throw new IllegalArgumentException("bridge error code must be snake_case");
    }
    if (message == null || message.isBlank()) {
      throw new IllegalArgumentException("bridge error message must not be blank");
    }
    details = details == null ? Map.of() : Map.copyOf(details);
  }

  /**
   * Converts this error into its wire-level JSON object representation.
   *
   * @return ordered map containing {@code status}, {@code code}, {@code message}, and optional metadata
   */
  public Map<String, Object> toMap() {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("status", status);
    result.put("code", code);
    result.put("message", message);
    if (target != null) result.put("target", target);
    if (!details.isEmpty()) result.put("details", details);
    return result;
  }
}
