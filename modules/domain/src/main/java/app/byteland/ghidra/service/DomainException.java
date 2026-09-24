package app.byteland.ghidra.service;

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
}
