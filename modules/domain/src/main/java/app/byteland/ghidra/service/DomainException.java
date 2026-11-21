package app.byteland.ghidra.service;

/**
 * Identifies domain errors with machine-readable codes and optional targets.
 */
public interface DomainException {
  /**
   * Returns the HTTP-compatible error status code.
   *
   * @return status code in {@code 400..599}
   */
  int status();

  /**
   * Returns the machine-readable error code.
   *
   * @return snake_case error code
   */
  String code();

  /**
   * Returns the error target name or identifier, or {@code null}.
   *
   * @return target field or pointer, or {@code null}
   */
  String target();
}
