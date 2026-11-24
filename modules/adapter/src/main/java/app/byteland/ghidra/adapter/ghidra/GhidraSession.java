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
   * Creates a session wrapper around an active Ghidra script.
   *
   * @param script active Ghidra script instance
   */
  public GhidraSession(GhidraScript script) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
  }

  /**
   * Returns the live Ghidra script instance.
   *
   * @return active Ghidra script
   */
  public GhidraScript script() {
    return ghidraScript;
  }

  /**
   * Returns the active Ghidra program or fails when none is open.
   *
   * @return active Ghidra program
   */
  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  /**
   * Returns the active Ghidra program, or null when no program is open.
   *
   * @return active Ghidra program or null
   */
  public Program currentProgramOrNull() {
    return ghidraScript.getCurrentProgram();
  }

  /**
   * Commits any ambient script transaction and saves the active program.
   */
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
   * Parses a raw address text value against the active program.
   *
   * @param rawAddress canonical or hex address text
   * @return resolved Ghidra address
   */
  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(ghidraScript, rawAddress);
  }

  /**
   * Returns references to or from the given program address.
   *
   * @param address target or source address
   * @param to true for inbound references, false for outbound references
   * @return iterable of Ghidra references
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
   * Runs an operation inside a committed program transaction.
   *
   * @param operation transactional operation to run
   * @param <T> operation result type
   * @return operation result
   */
  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(operation, true);
  }

  /**
   * Runs an operation inside a temporary transaction that reverts on completion.
   *
   * @param operation transactional operation to run
   * @param <T> operation result type
   * @return operation result
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
   * Executes a Ghidra command against the active program or fails on command error.
   *
   * @param command Ghidra program command
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
   * Represents a checked operation executed inside a Ghidra transaction.
   *
   * @param <T> operation result type
   */
  @FunctionalInterface
  public interface TransactionalOperation<T> {
    /**
     * Runs the transactional work.
     *
     * @return operation result
     * @throws Exception if the operation fails
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
