package app.byteland.ghidra.adapter.ghidra;

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

  public GhidraSession(GhidraScript script) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
  }

  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "Adapter collaborators require the live GhidraScript execution context")
  public GhidraScript script() {
    return ghidraScript;
  }

  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  public Program currentProgramOrNull() {
    return ghidraScript.getCurrentProgram();
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  public void saveCurrentProgram() {
    synchronized (executionLock) {
      var monitor = ghidraScript.getMonitor();
      boolean restoreCancellation = monitor != null && monitor.isCancelled();
      if (restoreCancellation) {
        monitor.clearCancelled();
      }
      try {
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

  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(ghidraScript, rawAddress);
  }

  public java.util.List<ghidra.program.model.symbol.Reference> references(
      Address address, boolean to) {
    return java.util.Arrays.asList(
        to ? ghidraScript.getReferencesTo(address) : ghidraScript.getReferencesFrom(address));
  }

  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(operation, true);
  }

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
    throw new IllegalArgumentException(failurePrefix + ": " + status);
  }

  @FunctionalInterface
  public interface TransactionalOperation<T> {
    T run() throws Exception;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static <T> T runOperation(TransactionalOperation<T> operation) {
    try {
      return operation.run();
    } catch (RuntimeException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }
}
