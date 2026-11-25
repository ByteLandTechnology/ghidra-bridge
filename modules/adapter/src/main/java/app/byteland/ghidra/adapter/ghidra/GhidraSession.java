package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession {
  /**
   * Receives notifications after committed transactions, commands, or analysis runs.
   */
  @FunctionalInterface
  public interface MutationListener {
    /**
     * Reports a committed mutation. A null address set indicates a full-program mutation.
     */
    void onProgramMutated(AddressSetView affectedAddresses);
  }

  private final GhidraScript ghidraScript;
  private final Object executionLock = new Object();
  private final List<MutationListener> mutationListeners = new CopyOnWriteArrayList<>();
  private int transactionDepth;
  private AddressSet pendingMutatedAddresses;
  private boolean pendingUnscopedMutation;

  public GhidraSession(GhidraScript script) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
  }

  public void addMutationListener(MutationListener listener) {
    mutationListeners.add(Objects.requireNonNull(listener, "listener"));
  }

  public void recordMutatedRange(Address start, Address end) {
    if (start == null) {
      notifyProgramMutated(null);
      return;
    }
    Address effectiveEnd = end == null ? start : end;
    if (!start.getAddressSpace().equals(effectiveEnd.getAddressSpace())) {
      notifyProgramMutated(null);
      return;
    }
    Address min = start.compareTo(effectiveEnd) <= 0 ? start : effectiveEnd;
    Address max = start.compareTo(effectiveEnd) <= 0 ? effectiveEnd : start;
    synchronized (executionLock) {
      if (transactionDepth > 0 && pendingMutatedAddresses != null) {
        pendingMutatedAddresses.add(min, max);
        return;
      }
    }
    notifyProgramMutated(new AddressSet(min, max));
  }

  public void notifyProgramMutated(AddressSetView affectedAddresses) {
    for (MutationListener listener : mutationListeners) {
      listener.onProgramMutated(affectedAddresses);
    }
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
      pendingMutatedAddresses = new AddressSet();
      pendingUnscopedMutation = false;
      boolean commit = false;
      AddressSet committedRanges = null;
      boolean unscoped = false;
      try {
        T result = runOperation(operation);
        commit = commitChanges;
        return result;
      } finally {
        committedRanges = pendingMutatedAddresses;
        unscoped = pendingUnscopedMutation;
        pendingMutatedAddresses = null;
        pendingUnscopedMutation = false;
        transactionDepth--;
        try {
          ghidraScript.end(commit);
        } finally {
          ghidraScript.start();
        }
        if (commit) {
          AddressSetView affected =
              unscoped || committedRanges == null || committedRanges.isEmpty()
                  ? null
                  : committedRanges;
          notifyProgramMutated(affected);
        }
      }
    }
  }

  public void runCommand(Command<Program> command, String failurePrefix) {
    Objects.requireNonNull(command, "command");
    boolean notifyStandalone = false;
    synchronized (executionLock) {
      if (ghidraScript.runCommand(command)) {
        if (transactionDepth > 0) {
          if (!command.getClass().getSimpleName().contains("Label")) {
            pendingUnscopedMutation = true;
          }
        } else {
          notifyStandalone = true;
        }
        if (notifyStandalone) {
          notifyProgramMutated(null);
        }
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
