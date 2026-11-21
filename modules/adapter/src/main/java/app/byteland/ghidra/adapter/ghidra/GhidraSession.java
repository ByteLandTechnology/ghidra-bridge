package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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
   * Creates a session backed by the given {@link GhidraScript}.
   *
   * @param script active Ghidra script context
   */
  public GhidraSession(GhidraScript script) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
  }

  /**
   * Returns the underlying {@link GhidraScript} execution context.
   *
   * @return active Ghidra script context
   */
  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "Adapter collaborators require the live GhidraScript execution context")
  public GhidraScript script() {
    return ghidraScript;
  }

  /**
   * Returns the currently open Ghidra {@link Program}, failing if none is open.
   *
   * @return open Ghidra program
   */
  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  /**
   * Returns the currently open Ghidra {@link Program}, or {@code null} if none is open.
   *
   * @return open Ghidra program, or {@code null}
   */
  public Program currentProgramOrNull() {
    return ghidraScript.getCurrentProgram();
  }

  /**
   * Commits any active ambient script transaction and saves the current program.
   */
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
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
   * Parses an address string against the active script context.
   *
   * @param rawAddress raw address text
   * @return resolved Ghidra address
   */
  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(ghidraScript, rawAddress);
  }

  /**
   * Returns references to or from the given address.
   *
   * @param address target or source address
   * @param to {@code true} to read incoming references, {@code false} for outgoing references
   * @return matching Ghidra references
   */
  public java.util.List<ghidra.program.model.symbol.Reference> references(
      Address address, boolean to) {
    return java.util.Arrays.asList(
        to ? ghidraScript.getReferencesTo(address) : ghidraScript.getReferencesFrom(address));
  }

  /**
   * Runs an operation inside a committed Ghidra program transaction.
   *
   * @param <T> operation return type
   * @param operation transactional callback
   * @return result returned by {@code operation}
   */
  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(operation, true);
  }

  /**
   * Runs an operation inside a rolled-back Ghidra program transaction.
   *
   * @param <T> operation return type
   * @param operation transactional callback whose program mutations are discarded
   * @return result returned by {@code operation}
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
   * Executes a Ghidra {@link Command} against the active program, throwing on failure.
   *
   * @param command Ghidra program command
   * @param failurePrefix message prefix used when the command reports failure
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
   * Callback executed inside a Ghidra transaction boundary.
   *
   * @param <T> operation result type
   */
  @FunctionalInterface
  public interface TransactionalOperation<T> {
    /**
     * Runs the transactional work.
     *
     * @return operation result
     * @throws Exception when the underlying Ghidra operation fails
     */
    T run() throws Exception;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
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
