package app.byteland.ghidra.api;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Structured error payload returned in JSON-RPC error responses and batch item failures.
 *
 * @param status HTTP-compatible error status code in {@code 400..599}
 * @param code snake_case machine-readable error code
 * @param message non-blank human-readable error message
 * @param target optional JSON pointer identifying the offending input field
 * @param details optional structured diagnostic details
 */
public record BridgeError(
    int status, String code, String message, String target, Map<String, Object> details) {
  /** Validates status range, error code syntax, message text, and copies details. */
  public BridgeError {
    if (status < 400 || status > 599) {
      throw new IllegalArgumentException("bridge error status must be in 400..599");
    }
    if (code == null || !code.matches("[a-z][a-z0-9_]*")) {
      throw new IllegalArgumentException("bridge error code must be snake_case");
    }
    if (message == null || message.isBlank()) {
      throw new IllegalArgumentException("bridge error message must not be blank");
    }
    details = details == null ? Map.of() : Map.copyOf(details);
  }

  /**
   * Converts this error into its wire JSON object map representation.
   *
   * @return ordered wire error map
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
