package app.byteland.ghidra.service;

/**
 * Runs an operation inside a program transaction.
 */
@FunctionalInterface
public interface TransactionRunner {
  /**
   * Runs the given operation inside a transaction.
   *
   * @param operation operation to run
   * @param <T> result type
   * @return result of the operation
   */
  <T> T run(Operation<T> operation);

  /**
   * Represents an operation to run inside a program transaction.
   *
   * @param <T> result type
   */
  @FunctionalInterface
  interface Operation<T> {
    T execute() throws Exception;
  }
}
