package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.lang.ref.WeakReference;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.function.BooleanSupplier;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession implements AutoCloseable {
  private final GhidraScript ghidraScript;
  private final QuerySnapshotCache querySnapshots;
  private final BooleanSupplier analyzingSupplier;
  private final boolean allowProxySnapshots;
  private final Object executionLock = new Object();
  private volatile WeakReference<Program> snapshotProgram = new WeakReference<>(null);
  private int transactionDepth;

  public GhidraSession(GhidraScript script) {
    this(
        script,
        new QuerySnapshotCache(),
        () -> {
          Program program = script.getCurrentProgram();
          return program != null
              && !Proxy.isProxyClass(program.getClass())
              && AutoAnalysisManager.hasAutoAnalysisManager(program)
              && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
        },
        false);
  }

  public GhidraSession(
      GhidraScript script,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier) {
    this(script, querySnapshots, analyzingSupplier, true);
  }

  private GhidraSession(
      GhidraScript script,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier,
      boolean allowProxySnapshots) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
    this.querySnapshots = Objects.requireNonNull(querySnapshots, "querySnapshots");
    this.analyzingSupplier = Objects.requireNonNull(analyzingSupplier, "analyzingSupplier");
    this.allowProxySnapshots = allowProxySnapshots;
  }

  public GhidraScript script() {
    return ghidraScript;
  }

  public QuerySnapshotCache querySnapshots() {
    Program program = currentProgramOrNull();
    if (!snapshotProgram.refersTo(program)) {
      synchronized (querySnapshots) {
        if (!snapshotProgram.refersTo(program)) {
          querySnapshots.clear();
          snapshotProgram = new WeakReference<>(program);
        }
      }
    }
    return querySnapshots;
  }

  public long modificationNumber() {
    Program program = currentProgramOrNull();
    return program == null ? 0L : program.getModificationNumber();
  }

  public boolean isAnalyzing() {
    return analyzingSupplier.getAsBoolean();
  }

  public boolean canCacheSnapshots() {
    Program program = currentProgramOrNull();
    if (program == null) {
      return false;
    }
    if (!allowProxySnapshots && Proxy.isProxyClass(program.getClass())) {
      return false;
    }
    return !isAnalyzing();
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
    Objects.requireNonNull(address, "address");
    ReferenceManager manager = currentProgram().getReferenceManager();
    if (to) {
      return () -> {
        ReferenceIterator incoming = manager.getReferencesTo(address);
        return incoming == null ? Collections.emptyIterator() : incoming;
      };
    }
    Reference[] outgoing = manager.getReferencesFrom(address);
    return outgoing == null ? List.of() : Arrays.asList(outgoing);
  }

  public Reference reference(Address fromAddress, Address toAddress, int operandIndex) {
    Objects.requireNonNull(fromAddress, "fromAddress");
    Objects.requireNonNull(toAddress, "toAddress");
    return currentProgram().getReferenceManager().getReference(fromAddress, toAddress, operandIndex);
  }

  public byte[] readBytes(Address start, int length) throws MemoryAccessException {
    Objects.requireNonNull(start, "start");
    byte[] bytes = new byte[length];
    currentProgram().getMemory().getBytes(start, bytes);
    return bytes;
  }

  public Function functionAfter(Function function) {
    return function == null ? null : functionAfter(function.getEntryPoint());
  }

  public Function functionAfter(Address address) {
    Objects.requireNonNull(address, "address");
    FunctionIterator iterator = currentProgram().getListing().getFunctions(address, true);
    if (!iterator.hasNext()) {
      return null;
    }
    Function candidate = iterator.next();
    if (address.equals(candidate.getEntryPoint())) {
      return iterator.hasNext() ? iterator.next() : null;
    }
    return candidate;
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
