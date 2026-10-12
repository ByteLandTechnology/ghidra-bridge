package app.byteland.ghidra.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Indicates an internal failure during Ghidra database transaction or command execution.
 */
public class TransactionExecutionException extends RuntimeException implements DomainException {
  private static final long serialVersionUID = 1L;
  private final String target;
  private final Map<String, Object> details;

  public TransactionExecutionException(String message) {
    this(message, null, null, null);
  }

  public TransactionExecutionException(String message, Throwable cause) {
    this(message, null, null, cause);
  }

  public TransactionExecutionException(String message, String target) {
    this(message, target, null, null);
  }

  public TransactionExecutionException(String message, String target, Throwable cause) {
    this(message, target, null, cause);
  }

  public TransactionExecutionException(String message, Map<String, Object> details) {
    this(message, null, details, null);
  }

  public TransactionExecutionException(
      String message, Map<String, Object> details, Throwable cause) {
    this(message, null, details, cause);
  }

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

  public Map<String, Object> details() {
    return details;
  }
}
