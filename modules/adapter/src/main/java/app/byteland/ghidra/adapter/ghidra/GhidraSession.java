package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.Objects;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession {
  private final GhidraScript ghidraScript;
  private final Object executionLock = new Object();
  private int transactionDepth;

  /**
   * Creates a session bound to a running {@link GhidraScript}.
   *
   * @param script active Ghidra script instance
   */
  public GhidraSession(GhidraScript script) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
  }

  /**
   * Returns the underlying {@link GhidraScript} instance.
   *
   * @return bound Ghidra script
   */
  public GhidraScript script() {
    return ghidraScript;
  }

  /**
   * Returns the open Ghidra program, throwing if no program is active.
   *
   * @return active {@link Program}
   */
  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  /**
   * Returns the open Ghidra program, or {@code null} if none is open.
   *
   * @return active {@link Program}, or {@code null}
   */
  public Program currentProgramOrNull() {
    return ghidraScript.getCurrentProgram();
  }

  /** Commits any open script transaction and saves the current program to the project repository. */
  public void saveCurrentProgram() {
    synchronized (executionLock) {
      var monitor = ghidraScript.getMonitor();
      boolean restoreCancellation = monitor != null && monitor.isCancelled();
      if (restoreCancellation) {
        monitor.clearCancelled();
      }
      try {
        try {
          ghidraScript.end(true);
        } catch (Exception ignored) {
          // There is no ambient transaction, or the transaction ended.
        }
        ghidraScript.saveProgram(currentProgram());
      } catch (Exception error) {
        String detail = error.getMessage();
        if (detail == null || detail.isBlank()) {
          detail = error.getClass().getSimpleName();
        }
        throw new IllegalStateException("Unable to save current program: " + detail, error);
      } finally {
        if (restoreCancellation) {
          monitor.cancel();
        }
      }
    }
  }

  /**
   * Parses {@code rawAddress} against the active program's address factory.
   *
   * @param rawAddress raw address text
   * @return resolved {@link Address}
   */
  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(ghidraScript, rawAddress);
  }

  /**
   * Returns incoming or outgoing references associated with {@code address}.
   *
   * @param address target or source program address
   * @param to {@code true} for incoming references to {@code address}, or {@code false} for
   *     outgoing references from {@code address}
   * @return iterable of matching Ghidra references
   */
  public Iterable<ghidra.program.model.symbol.Reference> references(Address address, boolean to) {
    ghidra.program.model.symbol.ReferenceManager manager = currentProgram().getReferenceManager();
    if (to) {
      return () -> {
        ghidra.program.model.symbol.ReferenceIterator incoming = manager.getReferencesTo(address);
        return incoming == null ? java.util.Collections.emptyIterator() : incoming;
      };
    }
    ghidra.program.model.symbol.Reference[] outgoing = manager.getReferencesFrom(address);
    return outgoing == null ? java.util.List.of() : java.util.Arrays.asList(outgoing);
  }

  /**
   * Executes {@code operation} inside a committed Ghidra program transaction.
   *
   * @param <T> operation return type
   * @param operation transactional callback to execute
   * @return callback result
   */
  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(operation, true);
  }

  /**
   * Executes {@code operation} inside an independent Ghidra transaction that is rolled back on exit.
   *
   * @param <T> operation return type
   * @param operation transactional callback to execute
   * @return callback result
   */
  public <T> T withTemporaryChanges(TransactionalOperation<T> operation) {
    return withTransaction(operation, false);
  }

  private <T> T withTransaction(TransactionalOperation<T> operation, boolean commitChanges) {
    Objects.requireNonNull(operation, "operation");
    synchronized (executionLock) {
      if (transactionDepth > 0) {
        if (!commitChanges) {
          throw new IllegalStateException("Temporary changes require an independent transaction");
        }
        return runOperation(operation);
      }

      ghidraScript.end(true);
      ghidraScript.start();
      transactionDepth++;
      boolean commit = false;
      try {
        T result = runOperation(operation);
        commit = commitChanges;
        return result;
      } finally {
        transactionDepth--;
        try {
          ghidraScript.end(commit);
        } finally {
          ghidraScript.start();
        }
      }
    }
  }

  /**
   * Runs {@code command} against the open program or throws {@link TransactionExecutionException}.
   *
   * @param command Ghidra command to execute
   * @param failurePrefix message prefix used when the command fails
   */
  public void runCommand(Command<Program> command, String failurePrefix) {
    Objects.requireNonNull(command, "command");
    synchronized (executionLock) {
      if (ghidraScript.runCommand(command)) {
        return;
      }
    }
    String status = command.getStatusMsg();
    if (status == null || status.isBlank()) {
      status = "command failed";
    }
    throw new TransactionExecutionException(failurePrefix + ": " + status);
  }

  /**
   * Callback executed inside a Ghidra program transaction.
   *
   * @param <T> callback result type
   */
  @FunctionalInterface
  public interface TransactionalOperation<T> {
    /**
     * Executes transactional work against the current program.
     *
     * @return operation result
     * @throws Exception if execution fails
     */
    T run() throws Exception;
  }

  private static <T> T runOperation(TransactionalOperation<T> operation) {
    try {
      return operation.run();
    } catch (RuntimeException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new TransactionExecutionException(ex.getMessage(), ex);
    }
  }
}
