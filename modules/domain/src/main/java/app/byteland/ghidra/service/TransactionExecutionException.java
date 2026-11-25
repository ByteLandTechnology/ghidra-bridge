package app.byteland.ghidra.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Indicates an internal failure during a Ghidra database transaction or command.
 */
public class TransactionExecutionException extends RuntimeException implements DomainException {
  private static final long serialVersionUID = 1L;
  /** Optional offending field or target identifier associated with this transaction failure. */
  private final String target;
  private final transient Map<String, Object> details;

  /**
   * Creates a transaction failure with a message and no target or cause.
   *
   * @param message human-readable failure message
   */
  public TransactionExecutionException(String message) {
    this(message, null, null, null);
  }

  /**
   * Creates a transaction failure with a message and underlying cause.
   *
   * @param message human-readable failure message
   * @param cause underlying exception cause, or {@code null}
   */
  public TransactionExecutionException(String message, Throwable cause) {
    this(message, null, null, cause);
  }

  /**
   * Creates a transaction failure with a message and offending target path.
   *
   * @param message human-readable failure message
   * @param target offending field or target identifier, or {@code null}
   */
  public TransactionExecutionException(String message, String target) {
    this(message, target, null, null);
  }

  /**
   * Creates a transaction failure with a message, target path, and cause.
   *
   * @param message human-readable failure message
   * @param target offending field or target identifier, or {@code null}
   * @param cause underlying exception cause, or {@code null}
   */
  public TransactionExecutionException(String message, String target, Throwable cause) {
    this(message, target, null, cause);
  }

  /**
   * Creates a transaction failure with a message and structured diagnostic details.
   *
   * @param message human-readable failure message
   * @param details structured diagnostic metadata, or {@code null}
   */
  public TransactionExecutionException(String message, Map<String, Object> details) {
    this(message, null, details, null);
  }

  /**
   * Creates a transaction failure with a message, structured diagnostic details, and cause.
   *
   * @param message human-readable failure message
   * @param details structured diagnostic metadata, or {@code null}
   * @param cause underlying exception cause, or {@code null}
   */
  public TransactionExecutionException(
      String message, Map<String, Object> details, Throwable cause) {
    this(message, null, details, cause);
  }

  /**
   * Creates a transaction failure with full message, target, details, and cause metadata.
   *
   * @param message human-readable failure message
   * @param target offending field or target identifier, or {@code null}
   * @param details structured diagnostic metadata, or {@code null}
   * @param cause underlying exception cause, or {@code null}
   */
  public TransactionExecutionException(
      String message, String target, Map<String, Object> details, Throwable cause) {
    super(message, cause);
    this.target = target;
    this.details =
        details == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(details));
  }

  @Override
  public int status() {
    return 500;
  }

  @Override
  public String code() {
    return "transaction_failed";
  }

  @Override
  public String target() {
    return target;
  }

  /**
   * Returns structured diagnostic details attached to this failure.
   *
   * @return unmodifiable diagnostic details map, or an empty map
   */
  public Map<String, Object> details() {
    return details == null ? Map.of() : details;
  }
}
