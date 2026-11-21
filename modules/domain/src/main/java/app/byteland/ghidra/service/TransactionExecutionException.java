package app.byteland.ghidra.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Indicates an internal failure during a Ghidra database transaction or command.
 */
public class TransactionExecutionException extends RuntimeException implements DomainException {
  private static final long serialVersionUID = 1L;

  /**
   * Optional error target identifier.
   *
   * @serial
   */
  private final String errorTarget;

  private final transient Map<String, Object> errorDetails;

  /**
   * Creates an exception with an error message.
   *
   * @param message failure description
   */
  public TransactionExecutionException(String message) {
    this(message, null, null, null);
  }

  /**
   * Creates an exception with an error message and cause.
   *
   * @param message failure description
   * @param cause underlying failure cause
   */
  public TransactionExecutionException(String message, Throwable cause) {
    this(message, null, null, cause);
  }

  /**
   * Creates an exception with an error message and target identifier.
   *
   * @param message failure description
   * @param target optional target identifier
   */
  public TransactionExecutionException(String message, String target) {
    this(message, target, null, null);
  }

  /**
   * Creates an exception with an error message, target identifier, and cause.
   *
   * @param message failure description
   * @param target optional target identifier
   * @param cause underlying failure cause
   */
  public TransactionExecutionException(String message, String target, Throwable cause) {
    this(message, target, null, cause);
  }

  /**
   * Creates an exception with an error message and diagnostic details.
   *
   * @param message failure description
   * @param details optional diagnostic key-value map
   */
  public TransactionExecutionException(String message, Map<String, Object> details) {
    this(message, null, details, null);
  }

  /**
   * Creates an exception with an error message, diagnostic details, and cause.
   *
   * @param message failure description
   * @param details optional diagnostic key-value map
   * @param cause underlying failure cause
   */
  public TransactionExecutionException(
      String message, Map<String, Object> details, Throwable cause) {
    this(message, null, details, cause);
  }

  /**
   * Creates an exception with an error message, target identifier, diagnostic details, and cause.
   *
   * @param message failure description
   * @param target optional target identifier
   * @param details optional diagnostic key-value map
   * @param cause underlying failure cause
   */
  public TransactionExecutionException(
      String message, String target, Map<String, Object> details, Throwable cause) {
    super(message, cause);
    this.errorTarget = target;
    this.errorDetails =
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
    return errorTarget;
  }

  /**
   * Returns diagnostic details attached to this failure, or an empty map after deserialization.
   *
   * @return unmodifiable diagnostic detail map
   */
  public Map<String, Object> details() {
    return errorDetails == null ? Map.of() : Collections.unmodifiableMap(errorDetails);
  }
}
