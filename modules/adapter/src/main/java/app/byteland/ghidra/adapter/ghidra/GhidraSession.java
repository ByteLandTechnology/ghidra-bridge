package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.cmd.Command;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Coordinates Ghidra program access, commands, transaction lifecycles, and session C++ indexing.
 */
public final class GhidraSession implements BridgeServices.SessionCloseable {
  private final GhidraScript ghidraScript;
  private final ReentrantLock executionLock = new ReentrantLock();
  private final AtomicInteger bridgeAnalysisDepth = new AtomicInteger();
  private final CppSymbolIndex cppSymbols;
  private volatile int transactionDepth;

  public GhidraSession(GhidraScript script) {
    this(script, CppSymbolIndex.Config.defaults(), DemanglerUtil::demangle);
  }

  public GhidraSession(
      GhidraScript script,
      CppSymbolIndex.Config indexConfig,
      CppSymbolIndex.Demangler demangler) {
    this.ghidraScript = Objects.requireNonNull(script, "script");
    this.cppSymbols = new CppSymbolIndex(this, indexConfig, demangler);
  }

  public CppSymbolIndex cppSymbols() {
    return cppSymbols;
  }

  public void startCppSymbolPrewarm() {
    cppSymbols.startPrewarm();
  }

  public boolean holdsExecutionLock() {
    return executionLock.isHeldByCurrentThread();
  }

  public void onAnalysisStarted() {
    bridgeAnalysisDepth.incrementAndGet();
    cppSymbols.onSessionStateChanged();
  }

  public void onAnalysisFinished() {
    bridgeAnalysisDepth.decrementAndGet();
    cppSymbols.onSessionStateChanged();
  }

  @Override
  public void close() {
    cppSymbols.close();
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
    executionLock.lock();
    try {
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
    } finally {
      unlockAndNotify();
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
    executionLock.lock();
    try {
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
    } finally {
      unlockAndNotify();
    }
  }

  public void runCommand(Command<Program> command, String failurePrefix) {
    Objects.requireNonNull(command, "command");
    executionLock.lock();
    try {
      if (ghidraScript.runCommand(command)) {
        return;
      }
    } finally {
      unlockAndNotify();
    }
    String status = command.getStatusMsg();
    if (status == null || status.isBlank()) {
      status = "command failed";
    }
    throw new TransactionExecutionException(failurePrefix + ": " + status);
  }

  boolean isPausedForPrewarm(Program program) {
    return transactionDepth > 0
        || executionLock.isLocked()
        || bridgeAnalysisDepth.get() > 0
        || isGhidraAnalyzing(program);
  }

  <T> T tryCollectForPrewarm(Program program, Supplier<T> collector, T pausedValue) {
    if (transactionDepth > 0 || bridgeAnalysisDepth.get() > 0 || isGhidraAnalyzing(program)) {
      return pausedValue;
    }
    if (!executionLock.tryLock()) {
      return pausedValue;
    }
    try {
      if (transactionDepth > 0 || bridgeAnalysisDepth.get() > 0 || isGhidraAnalyzing(program)) {
        return pausedValue;
      }
      return collector.get();
    } finally {
      executionLock.unlock();
    }
  }

  private void unlockAndNotify() {
    executionLock.unlock();
    if (!executionLock.isHeldByCurrentThread()) {
      cppSymbols.onSessionStateChanged();
    }
  }

  private static boolean isGhidraAnalyzing(Program program) {
    return program != null
        && AutoAnalysisManager.hasAutoAnalysisManager(program)
        && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
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
