package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.program.ProgramHistoryConflictException;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.Objects;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession {
  private static final String DEFAULT_TRANSACTION_NAME = "bridge.write";
  private static final String TEMPORARY_TRANSACTION_NAME = "bridge.temporary";

  private final GhidraScript ghidraScript;
  private final Object executionLock = new Object();
  private int transactionDepth;

  public GhidraSession(GhidraScript script) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
    endAmbientScriptTransaction();
  }

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

  public void saveCurrentProgram() {
    synchronized (executionLock) {
      var monitor = ghidraScript.getMonitor();
      boolean restoreCancellation = monitor != null && monitor.isCancelled();
      if (restoreCancellation) {
        monitor.clearCancelled();
      }
      try {
        endAmbientScriptTransaction();
        ghidraScript.saveProgram(currentProgram());
      } catch (Exception error) {
        String detail = error.getMessage();
        if (detail == null || detail.isBlank()) {
          detail = error.getClass().getSimpleName();
        }
        throw new IllegalStateException("Unable to save current program: " + detail, error);
      } finally {
        endAmbientScriptTransaction();
        if (restoreCancellation) {
          monitor.cancel();
        }
      }
    }
  }

  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(ghidraScript, rawAddress);
  }

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

  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(DEFAULT_TRANSACTION_NAME, operation, true);
  }

  public <T> T withTransaction(String description, TransactionalOperation<T> operation) {
    return withTransaction(description, operation, true);
  }

  public <T> T withTemporaryChanges(TransactionalOperation<T> operation) {
    return withTransaction(TEMPORARY_TRANSACTION_NAME, operation, false);
  }

  public <T> T withProgramLock(ProgramOperation<T> operation) {
    Objects.requireNonNull(operation, "operation");
    synchronized (executionLock) {
      Program program = currentProgram();
      try {
        return operation.run(program);
      } catch (RuntimeException ex) {
        throw ex;
      } catch (Exception ex) {
        throw new TransactionExecutionException(ex.getMessage(), ex);
      }
    }
  }

  public <T> T withIdleProgram(ProgramOperation<T> operation) {
    Objects.requireNonNull(operation, "operation");
    synchronized (executionLock) {
      if (transactionDepth > 0) {
        throw ProgramHistoryConflictException.transactionInProgress();
      }
      endAmbientScriptTransaction();
      Program program = currentProgram();
      if (program.getCurrentTransactionInfo() != null) {
        throw ProgramHistoryConflictException.transactionInProgress();
      }
      try {
        return operation.run(program);
      } catch (RuntimeException ex) {
        throw ex;
      } catch (Exception ex) {
        throw new TransactionExecutionException(ex.getMessage(), ex);
      }
    }
  }

  private <T> T withTransaction(
      String description, TransactionalOperation<T> operation, boolean commitChanges) {
    Objects.requireNonNull(operation, "operation");
    String transactionName =
        description == null || description.isBlank() ? DEFAULT_TRANSACTION_NAME : description;
    synchronized (executionLock) {
      if (transactionDepth > 0) {
        if (!commitChanges) {
          throw new IllegalStateException("Temporary changes require an independent transaction");
        }
        return runOperation(operation);
      }

      endAmbientScriptTransaction();
      Program program = currentProgramOrNull();
      int transactionId = program == null ? -1 : program.startTransaction(transactionName);
      transactionDepth++;
      boolean commit = false;
      try {
        T result = runOperation(operation);
        commit = commitChanges;
        return result;
      } finally {
        transactionDepth--;
        if (program != null) {
          program.endTransaction(transactionId, commit);
        }
      }
    }
  }

  private void endAmbientScriptTransaction() {
    try {
      ghidraScript.end(true);
    } catch (Exception ignored) {
      // No ambient script transaction is active.
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
    throw new TransactionExecutionException(failurePrefix + ": " + status);
  }

  @FunctionalInterface
  public interface TransactionalOperation<T> {
    T run() throws Exception;
  }

  @FunctionalInterface
  public interface ProgramOperation<T> {
    T run(Program program) throws Exception;
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
