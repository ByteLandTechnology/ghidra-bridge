package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession implements AutoCloseable {
  private final GhidraScript ghidraScript;
  private final QuerySnapshotCache querySnapshots;
  private final BooleanSupplier analyzingSupplier;
  private final Object executionLock = new Object();
  private int transactionDepth;

  public GhidraSession(GhidraScript script) {
    this(
        script,
        new QuerySnapshotCache(),
        () -> {
          Program program = script.getCurrentProgram();
          return program != null
              && AutoAnalysisManager.hasAutoAnalysisManager(program)
              && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
        });
  }

  public GhidraSession(
      GhidraScript script,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
    this.querySnapshots = Objects.requireNonNull(querySnapshots, "querySnapshots");
    this.analyzingSupplier = Objects.requireNonNull(analyzingSupplier, "analyzingSupplier");
  }

  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "Adapter collaborators require the live GhidraScript execution context")
  public GhidraScript script() {
    return ghidraScript;
  }

  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "Adapter query collaborators share the session-scoped snapshot cache")
  public QuerySnapshotCache querySnapshots() {
    return querySnapshots;
  }

  public long modificationNumber() {
    Program program = currentProgramOrNull();
    return program == null ? 0L : program.getModificationNumber();
  }

  public boolean isAnalyzing() {
    return analyzingSupplier.getAsBoolean();
  }

  @Override
  public void close() {
    querySnapshots.clear();
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

  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(ghidraScript, rawAddress);
  }

  public Iterable<Reference> references(Address address, boolean to) {
    if (to) {
      Program program = currentProgramOrNull();
      if (program != null && program.getReferenceManager() != null) {
        ReferenceManager referenceManager = program.getReferenceManager();
        return () -> referenceManager.getReferencesTo(address);
      }
      return Arrays.asList(ghidraScript.getReferencesTo(address));
    }
    return Arrays.asList(ghidraScript.getReferencesFrom(address));
  }

  public Reference reference(Address fromAddress, Address toAddress, int operandIndex) {
    Program program = currentProgramOrNull();
    if (program != null && program.getReferenceManager() != null) {
      return program.getReferenceManager().getReference(fromAddress, toAddress, operandIndex);
    }
    for (Reference candidate : references(fromAddress, false)) {
      if (toAddress.equals(candidate.getToAddress())
          && candidate.getOperandIndex() == operandIndex) {
        return candidate;
      }
    }
    return null;
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
          try {
            ghidraScript.start();
          } finally {
            querySnapshots.clear();
          }
        }
      }
    }
  }

  public void runCommand(Command<Program> command, String failurePrefix) {
    Objects.requireNonNull(command, "command");
    synchronized (executionLock) {
      try {
        if (ghidraScript.runCommand(command)) {
          return;
        }
      } finally {
        querySnapshots.clear();
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
