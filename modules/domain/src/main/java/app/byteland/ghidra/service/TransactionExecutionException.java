package app.byteland.ghidra.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Indicates an internal failure during a Ghidra database transaction or command.
 */
public class TransactionExecutionException extends RuntimeException implements DomainException {
  private static final long serialVersionUID = 1L;

  /** Optional field or path target associated with the failed transaction. */
  private final String target;

  private final transient Map<String, Object> details;

  /**
   * Creates a transaction failure with a message.
   *
   * @param message failure message
   */
  public TransactionExecutionException(String message) {
    this(message, null, null, null);
  }

  /**
   * Creates a transaction failure with a message and underlying cause.
   *
   * @param message failure message
   * @param cause underlying exception cause
   */
  public TransactionExecutionException(String message, Throwable cause) {
    this(message, null, null, cause);
  }

  /**
   * Creates a transaction failure targeting a specific request field or path.
   *
   * @param message failure message
   * @param target offending field or path identifier
   */
  public TransactionExecutionException(String message, String target) {
    this(message, target, null, null);
  }

  /**
   * Creates a transaction failure with a target path and underlying cause.
   *
   * @param message failure message
   * @param target offending field or path identifier
   * @param cause underlying exception cause
   */
  public TransactionExecutionException(String message, String target, Throwable cause) {
    this(message, target, null, cause);
  }

  /**
   * Creates a transaction failure with structured diagnostic details.
   *
   * @param message failure message
   * @param details structured error details map
   */
  public TransactionExecutionException(String message, Map<String, Object> details) {
    this(message, null, details, null);
  }

  /**
   * Creates a transaction failure with structured diagnostic details and underlying cause.
   *
   * @param message failure message
   * @param details structured error details map
   * @param cause underlying exception cause
   */
  public TransactionExecutionException(
      String message, Map<String, Object> details, Throwable cause) {
    this(message, null, details, cause);
  }

  /**
   * Creates a transaction failure with an optional target, diagnostic details, and cause.
   *
   * @param message failure message
   * @param target optional offending field or path identifier
   * @param details optional structured error details map
   * @param cause optional underlying exception cause
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
   * Returns an unmodifiable map of structured diagnostic details for this failure.
   *
   * @return diagnostic details map
   */
  public Map<String, Object> details() {
    return details == null ? Map.of() : Collections.unmodifiableMap(details);
  }
}
