package app.byteland.ghidra.service;

import java.util.Map;

/**
 * Identifies domain errors with machine-readable codes and optional targets.
 */
public interface DomainException {
  /** Returns the HTTP-compatible error status code. */
  int status();

  /** Returns the machine-readable error code. */
  String code();

  /** Returns the error target name or identifier, or null. */
  String target();

  /** Returns structured diagnostic details for this error. */
  default Map<String, Object> details() {
    return Map.of();
  }
}
