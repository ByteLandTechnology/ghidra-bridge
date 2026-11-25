package app.byteland.ghidra.service;

import java.io.Serial;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Indicates an internal failure during a Ghidra database transaction or command.
 */
public class TransactionExecutionException extends RuntimeException implements DomainException {
  @Serial
  private static final long serialVersionUID = 1L;

  /** Target name or identifier associated with the failure, or null. */
  private final String target;

  private final transient Map<String, Object> details;

  /**
   * Creates a transaction exception with an error message.
   *
   * @param message failure description
   */
  public TransactionExecutionException(String message) {
    this(message, null, null, null);
  }

  /**
   * Creates a transaction exception with an error message and cause.
   *
   * @param message failure description
   * @param cause root failure cause
   */
  public TransactionExecutionException(String message, Throwable cause) {
    this(message, null, null, cause);
  }

  /**
   * Creates a transaction exception with an error message and target.
   *
   * @param message failure description
   * @param target target name or pointer
   */
  public TransactionExecutionException(String message, String target) {
    this(message, target, null, null);
  }

  /**
   * Creates a transaction exception with an error message, target, and cause.
   *
   * @param message failure description
   * @param target target name or pointer
   * @param cause root failure cause
   */
  public TransactionExecutionException(String message, String target, Throwable cause) {
    this(message, target, null, cause);
  }

  /**
   * Creates a transaction exception with an error message and structured details.
   *
   * @param message failure description
   * @param details structured error metadata
   */
  public TransactionExecutionException(String message, Map<String, Object> details) {
    this(message, null, details, null);
  }

  /**
   * Creates a transaction exception with an error message, structured details, and cause.
   *
   * @param message failure description
   * @param details structured error metadata
   * @param cause root failure cause
   */
  public TransactionExecutionException(
      String message, Map<String, Object> details, Throwable cause) {
    this(message, null, details, cause);
  }

  /**
   * Creates a transaction exception with an error message, target, details, and cause.
   *
   * @param message failure description
   * @param target target name or pointer
   * @param details structured error metadata
   * @param cause root failure cause
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
   * Returns structured metadata associated with this transaction failure.
   *
   * @return unmodifiable map of failure details
   */
  public Map<String, Object> details() {
    return details == null ? Map.of() : details;
  }
}
