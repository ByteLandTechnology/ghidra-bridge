package app.byteland.ghidra.service;

/**
 * Identifies domain errors with machine-readable codes and optional targets.
 */
public interface DomainException {
  /**
   * Returns the HTTP-compatible error status code.
   *
   * @return numeric status code
   */
  int status();

  /**
   * Returns the machine-readable error code.
   *
   * @return stable error code string
   */
  String code();

  /**
   * Returns the error target name or identifier, or null.
   *
   * @return target identifier or null
   */
  String target();
}
