package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.framework.cmd.Command;
import ghidra.program.flatapi.FlatProgramAPI;
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
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Coordinates Ghidra program access, commands, transaction lifecycles, and session C++ indexing.
 */
public final class GhidraSession implements AutoCloseable {
  private final ProgramHost host;
  private final QuerySnapshotCache querySnapshots;
  private final BooleanSupplier analyzingSupplier;
  private final boolean allowProxySnapshots;
  private final ReentrantLock executionLock = new ReentrantLock();
  private final List<Consumer<Program>> programCloseListeners = new CopyOnWriteArrayList<>();
  private final AtomicInteger bridgeAnalysisDepth = new AtomicInteger();
  private final Object analysisProgramsLock = new Object();
  private final Map<Program, Integer> analyzingPrograms = new IdentityHashMap<>();
  private volatile boolean hasAnalyzingPrograms;
  private final CppSymbolIndex cppSymbols;
  private volatile WeakReference<Program> snapshotProgram = new WeakReference<>(null);
  private volatile WeakReference<Program> indexedProgram = new WeakReference<>(null);
  private volatile int transactionDepth;
  private Program pinnedProgram;

  public GhidraSession(GhidraScript script) {
    this(ProgramHost.forScript(Objects.requireNonNull(script, "script")));
  }

  public GhidraSession(Supplier<Program> programSupplier) {
    this(ProgramHost.forProgramSupplier(Objects.requireNonNull(programSupplier, "programSupplier")));
  }

  public GhidraSession(ProgramHost host) {
    this(host, new QuerySnapshotCache(), null, false, null, null);
  }

  public GhidraSession(
      GhidraScript script,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier) {
    this(
        ProgramHost.forScript(Objects.requireNonNull(script, "script")),
        querySnapshots,
        Objects.requireNonNull(analyzingSupplier, "analyzingSupplier"),
        true,
        null,
        null);
  }

  public GhidraSession(
      ProgramHost host,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier) {
    this(
        host,
        querySnapshots,
        Objects.requireNonNull(analyzingSupplier, "analyzingSupplier"),
        true,
        null,
        null);
  }

  public GhidraSession(
      GhidraScript script, CppSymbolIndexConfig indexConfig, CppDemangler demangler) {
    this(
        ProgramHost.forScript(Objects.requireNonNull(script, "script")),
        indexConfig,
        demangler);
  }

  public GhidraSession(
      ProgramHost host, CppSymbolIndexConfig indexConfig, CppDemangler demangler) {
    this(
        host,
        new QuerySnapshotCache(),
        null,
        false,
        Objects.requireNonNull(indexConfig, "indexConfig"),
        Objects.requireNonNull(demangler, "demangler"));
  }

  private GhidraSession(
      ProgramHost host,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier,
      boolean allowProxySnapshots,
      CppSymbolIndexConfig customConfig,
      CppDemangler customDemangler) {
    this.host = Objects.requireNonNull(host, "host");
    this.querySnapshots = Objects.requireNonNull(querySnapshots, "querySnapshots");
    this.analyzingSupplier = analyzingSupplier;
    this.allowProxySnapshots = allowProxySnapshots;
    this.cppSymbols =
        customConfig == null
            ? new CppSymbolIndex(this)
            : new CppSymbolIndex(
                this,
                customConfig,
                customDemangler != null ? customDemangler : DemanglerUtil::demangle);
    Program initial = host.currentProgramOrNull();
    if (initial != null) {
      this.indexedProgram = new WeakReference<>(initial);
      CppSymbolNames.bindSessionIndex(initial, this.cppSymbols);
    }
  }

  public FlatProgramAPI flatApi() {
    executionLock.lock();
    try {
      return host.flatApi(pinnedProgram);
    } finally {
      executionLock.unlock();
    }
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

  public CppSymbolIndex cppSymbols() {
    syncActiveProgram();
    return cppSymbols;
  }

  public void startCppSymbolPrewarm() {
    syncActiveProgram();
    Program current = currentProgramOrNull();
    if (current != null) {
      CppSymbolNames.bindSessionIndex(current, cppSymbols);
    }
    cppSymbols.startPrewarm();
  }

  public long modificationNumber() {
    Program program = currentProgramOrNull();
    return program == null ? 0L : program.getModificationNumber();
  }

  public boolean isAnalyzing() {
    return isAnalyzing(currentProgramOrNull());
  }

  boolean isAnalyzing(Program program) {
    if (bridgeAnalysisDepth.get() > 0) {
      return true;
    }
    if (program != null && hasAnalyzingPrograms && isBridgeAnalyzingProgram(program)) {
      return true;
    }
    if (analyzingSupplier != null) {
      return analyzingSupplier.getAsBoolean();
    }
    return program != null
        && !Proxy.isProxyClass(program.getClass())
        && AutoAnalysisManager.hasAutoAnalysisManager(program)
        && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
  }

  public boolean canCacheSnapshots() {
    return canCacheSnapshots(currentProgramOrNull());
  }

  boolean canCacheSnapshots(Program program) {
    if (program == null) {
      return false;
    }
    if (!allowProxySnapshots && Proxy.isProxyClass(program.getClass())) {
      return false;
    }
    return !isAnalyzing(program);
  }

  boolean canCacheSymbolSnapshot(Program program) {
    return program != null
        && !Proxy.isProxyClass(program.getClass())
        && !isAnalyzing(program);
  }

  public boolean holdsExecutionLock() {
    return executionLock.isHeldByCurrentThread();
  }

  public void onAnalysisStarted() {
    bridgeAnalysisDepth.incrementAndGet();
    querySnapshots.clear();
    cppSymbols.invalidateSnapshots();
    cppSymbols.onSessionStateChanged();
  }

  public void onAnalysisFinished() {
    bridgeAnalysisDepth.decrementAndGet();
    querySnapshots.clear();
    cppSymbols.onSessionStateChanged();
  }

  public void onAnalysisStarted(Program program) {
    if (program == null) {
      onAnalysisStarted();
      return;
    }
    synchronized (analysisProgramsLock) {
      analyzingPrograms.merge(program, 1, Integer::sum);
      hasAnalyzingPrograms = true;
    }
    if (snapshotProgram.refersTo(program)) {
      querySnapshots.clear();
    }
    if (indexedProgram.refersTo(program)) {
      cppSymbols.invalidateSnapshots();
      cppSymbols.onSessionStateChanged();
    }
  }

  public void onAnalysisFinished(Program program) {
    if (program == null) {
      onAnalysisFinished();
      return;
    }
    synchronized (analysisProgramsLock) {
      Integer count = analyzingPrograms.get(program);
      if (count != null) {
        if (count <= 1) {
          analyzingPrograms.remove(program);
        } else {
          analyzingPrograms.put(program, count - 1);
        }
      }
      hasAnalyzingPrograms = !analyzingPrograms.isEmpty();
    }
    if (snapshotProgram.refersTo(program)) {
      querySnapshots.clear();
    }
    if (indexedProgram.refersTo(program)) {
      cppSymbols.invalidateSnapshots();
      cppSymbols.onSessionStateChanged();
    }
  }

  private boolean isBridgeAnalyzingProgram(Program program) {
    synchronized (analysisProgramsLock) {
      return analyzingPrograms.containsKey(program);
    }
  }

  @Override
  public void close() {
    synchronized (querySnapshots) {
      querySnapshots.clear();
      snapshotProgram = new WeakReference<>(null);
    }
    synchronized (analysisProgramsLock) {
      analyzingPrograms.clear();
      hasAnalyzingPrograms = false;
    }
    Program bound = indexedProgram.get();
    CppSymbolNames.unbindSessionIndex(bound, cppSymbols);
    Program current = host.currentProgramOrNull();
    if (current != bound) {
      CppSymbolNames.unbindSessionIndex(current, cppSymbols);
    }
    cppSymbols.close();
  }

  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  public Program currentProgramOrNull() {
    if (executionLock.isHeldByCurrentThread() && pinnedProgram != null) {
      return pinnedProgram;
    }
    Program current = host.currentProgramOrNull();
    if (!indexedProgram.refersTo(current) && canSyncActiveProgramNow()) {
      syncActiveProgram();
    }
    return current;
  }

  public void onProgramClosed(Consumer<Program> listener) {
    programCloseListeners.add(Objects.requireNonNull(listener, "listener"));
  }

  public void notifyProgramClosed(Program program) {
    if (program == null) {
      return;
    }
    synchronized (analysisProgramsLock) {
      analyzingPrograms.remove(program);
      hasAnalyzingPrograms = !analyzingPrograms.isEmpty();
    }
    executionLock.lock();
    try {
      host.releaseProgram(program);
    } finally {
      executionLock.unlock();
    }
    if (snapshotProgram.refersTo(program)) {
      synchronized (querySnapshots) {
        if (snapshotProgram.refersTo(program)) {
          querySnapshots.clear();
          snapshotProgram = new WeakReference<>(null);
        }
      }
    }
    synchronized (cppSymbols) {
      CppSymbolNames.unbindSessionIndex(program, cppSymbols);
      if (indexedProgram.refersTo(program)) {
        cppSymbols.resetForProgramSwitch();
        indexedProgram = new WeakReference<>(null);
      }
    }
    if (host.currentProgramOrNull() != program) {
      syncActiveProgram();
    }
    cppSymbols.onSessionStateChanged();
    for (Consumer<Program> listener : programCloseListeners) {
      listener.accept(program);
    }
  }

  public void saveCurrentProgram() {
    executionLock.lock();
    try {
      try {
        host.saveProgram(currentProgram());
      } catch (Exception error) {
        String detail = error.getMessage();
        if (detail == null || detail.isBlank()) {
          detail = error.getClass().getSimpleName();
        }
        throw new IllegalStateException("Unable to save current program: " + detail, error);
      }
    } finally {
      unlockAndNotify();
    }
  }

  public Address parseAddress(String rawAddress) {
    Program program = currentProgramOrNull();
    if (program != null) {
      return AddressUtil.parseAddress(program, rawAddress);
    }
    return AddressUtil.parseAddress(flatApi(), rawAddress);
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
    return withTransaction(null, operation, true);
  }

  public <T> T withProgramTransaction(Program program, TransactionalOperation<T> operation) {
    return withTransaction(Objects.requireNonNull(program, "program"), operation, true);
  }

  public <T> T withTemporaryChanges(TransactionalOperation<T> operation) {
    return withTransaction(null, operation, false);
  }

  private <T> T withTransaction(
      Program explicitProgram, TransactionalOperation<T> operation, boolean commitChanges) {
    Objects.requireNonNull(operation, "operation");
    executionLock.lock();
    try {
      if (transactionDepth > 0) {
        if (!commitChanges) {
          throw new IllegalStateException("Temporary changes require an independent transaction");
        }
        if (explicitProgram != null && pinnedProgram != null && explicitProgram != pinnedProgram) {
          throw new IllegalStateException("Nested transaction targets a different program");
        }
        return runOperation(operation);
      }

      if (explicitProgram == null) {
        syncActiveProgram();
      }
      Program targetProgram = host.resolveTransactionProgram(explicitProgram);
      int transactionId = host.beginTransaction(targetProgram);
      pinnedProgram = targetProgram;
      transactionDepth++;
      boolean commit = false;
      try {
        T result = runOperation(operation);
        commit = commitChanges;
        return result;
      } finally {
        transactionDepth--;
        pinnedProgram = null;
        try {
          host.finishTransaction(targetProgram, transactionId, commit);
        } finally {
          querySnapshots.clear();
          if (targetProgram == null || indexedProgram.refersTo(targetProgram)) {
            cppSymbols.invalidateSnapshots();
          }
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
      try {
        if (transactionDepth == 0 && host.requiresCommandTransaction()) {
          if (withTransaction(() -> host.runCommand(currentProgram(), command))) {
            return;
          }
        } else if (host.runCommand(currentProgramOrNull(), command)) {
          return;
        }
      } finally {
        querySnapshots.clear();
        cppSymbols.invalidateSnapshots();
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

  Program peekCurrentProgramOrNull() {
    if (executionLock.isHeldByCurrentThread() && pinnedProgram != null) {
      return pinnedProgram;
    }
    return host.currentProgramOrNull();
  }

  boolean isIndexedProgram(Program program) {
    return indexedProgram.refersTo(program);
  }

  void syncActiveProgramIfIdle() {
    syncActiveProgram();
  }

  boolean isPausedForPrewarm(Program program) {
    return transactionDepth > 0
        || executionLock.isLocked()
        || isAnalyzing(program)
        || !indexedProgram.refersTo(program);
  }

  <T> T tryCollectForPrewarm(Program program, Supplier<T> collector, T pausedValue) {
    syncActiveProgram();
    if (transactionDepth > 0 || isAnalyzing(program) || !indexedProgram.refersTo(program)) {
      return pausedValue;
    }
    if (!executionLock.tryLock()) {
      return pausedValue;
    }
    try {
      if (transactionDepth > 0 || isAnalyzing(program) || !indexedProgram.refersTo(program)) {
        return pausedValue;
      }
      return collector.get();
    } finally {
      executionLock.unlock();
    }
  }

  private boolean canSyncActiveProgramNow() {
    return transactionDepth == 0
        && (!executionLock.isLocked() || executionLock.isHeldByCurrentThread());
  }

  private void syncActiveProgram() {
    if (!canSyncActiveProgramNow()) {
      return;
    }
    Program current = host.currentProgramOrNull();
    if (!indexedProgram.refersTo(current)) {
      synchronized (cppSymbols) {
        if (!canSyncActiveProgramNow()) {
          return;
        }
        current = host.currentProgramOrNull();
        if (!indexedProgram.refersTo(current)) {
          Program previous = indexedProgram.get();
          if (previous != null) {
            CppSymbolNames.unbindSessionIndex(previous, cppSymbols);
          }
          cppSymbols.resetForProgramSwitch();
          indexedProgram = new WeakReference<>(current);
          if (current != null && !cppSymbols.isClosed()) {
            CppSymbolNames.bindSessionIndex(current, cppSymbols);
          }
        }
      }
    }
  }

  private void unlockAndNotify() {
    executionLock.unlock();
    if (!executionLock.isHeldByCurrentThread()) {
      syncActiveProgram();
      cppSymbols.onSessionStateChanged();
    }
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
