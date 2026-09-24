package app.byteland.ghidra.api;

import java.util.LinkedHashMap;
import java.util.Map;

public record BridgeError(
    int status, String code, String message, String target, Map<String, Object> details) {
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
