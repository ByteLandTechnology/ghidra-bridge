package app.byteland.ghidra.service;

/**
 * Identifies domain errors with machine-readable codes and optional targets.
 */
public interface DomainException {
  /**
   * Returns the HTTP-compatible error status code.
   *
   * @return HTTP-equivalent status code
   */
  int status();

  /**
   * Returns the machine-readable error code.
   *
   * @return {@code snake_case} error code
   */
  String code();

  /**
   * Returns the error target name or identifier, or {@code null}.
   *
   * @return offending target identifier, or {@code null}
   */
  String target();
}
