package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.ExecutorShutdown;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Runs background C++ prefix scans in short lock slices and pauses during transactions or analysis.
 */
final class CppSymbolPrewarmer {
  private static final String[] MANGLED_PREFIXES = {"?", "_Z", "__Z"};
  private static final long PAUSE_POLL_MS = 25L;

  private record SymbolSample(String name, Address address) {}

  private final GhidraSession session;
  private final CppSymbolIndexConfig config;
  private final CppSymbolCache cache;
  private final CppSymbolIndex owner;

  private final Object stateLock = new Object();
  private ExecutorService executor;
  private Future<?> future;
  private boolean started;
  private boolean active;
  private boolean hasSyncedModification;
  private long syncedModificationNumber;
  private volatile boolean snapshotSkippedForSyncedMod;
  private volatile long fastSyncedMod = Long.MIN_VALUE;
  private boolean atCapacity;
  private volatile boolean closed;

  CppSymbolPrewarmer(
      GhidraSession session,
      CppSymbolIndexConfig config,
      CppSymbolCache cache,
      CppSymbolIndex owner) {
    this.session = Objects.requireNonNull(session, "session");
    this.config = Objects.requireNonNull(config, "config");
    this.cache = Objects.requireNonNull(cache, "cache");
    this.owner = Objects.requireNonNull(owner, "owner");
  }

  void start() {
    synchronized (stateLock) {
      if (closed || started) {
        return;
      }
      Program program = session.currentProgramOrNull();
      if (program == null) {
        return;
      }
      String programName =
          Proxy.isProxyClass(program.getClass()) ? "program" : program.getName();
      if (programName == null || programName.isBlank()) {
        programName = "program";
      }
      final String threadSuffix = programName;
      started = true;
      active = true;
      executor =
          Executors.newSingleThreadExecutor(
              runnable -> {
                Thread thread = new Thread(runnable, "ghidra-cpp-index-" + threadSuffix);
                thread.setDaemon(true);
                return thread;
              });
      future = executor.submit(this::runLoop);
    }
  }

  boolean isSyncedWithProgram(Program program) {
    if (program == null || closed || Proxy.isProxyClass(program.getClass())) {
      return false;
    }
    long modNumber = program.getModificationNumber();
    synchronized (stateLock) {
      return !closed
          && !atCapacity
          && hasSyncedModification
          && syncedModificationNumber == modNumber;
    }
  }

  void observeProgramModification(Program program, boolean evictionActive) {
    if (closed || evictionActive || program == null || Proxy.isProxyClass(program.getClass())) {
      return;
    }
    long modNumber = program.getModificationNumber();
    if (modNumber == fastSyncedMod
        && (snapshotSkippedForSyncedMod || owner.hasSymbolSnapshotFor(program, modNumber))) {
      return;
    }
    synchronized (stateLock) {
      if (closed || !started || atCapacity) {
        return;
      }
      if (!hasSyncedModification
          || syncedModificationNumber != modNumber
          || needsSnapshotRebuildLocked(program, modNumber)) {
        stateLock.notifyAll();
      }
    }
  }

  void markAtCapacity() {
    cache.markEvictionActive();
    synchronized (stateLock) {
      atCapacity = true;
      active = false;
      stateLock.notifyAll();
    }
  }

  void onStateChanged() {
    synchronized (stateLock) {
      if (!closed && started) {
        stateLock.notifyAll();
      }
    }
  }

  void resetForProgramSwitch() {
    synchronized (stateLock) {
      hasSyncedModification = false;
      syncedModificationNumber = 0L;
      snapshotSkippedForSyncedMod = false;
      fastSyncedMod = Long.MIN_VALUE;
      atCapacity = false;
      if (!closed && started) {
        stateLock.notifyAll();
      }
    }
  }

  boolean awaitQuiescence(Duration timeout) throws InterruptedException {
    Objects.requireNonNull(timeout, "timeout");
    long deadlineNanos = System.nanoTime() + Math.max(0L, timeout.toNanos());
    synchronized (stateLock) {
      while (!closed && started && needsOrRunningScanLocked()) {
        if (!active) {
          stateLock.notifyAll();
        }
        long remainingNanos = deadlineNanos - System.nanoTime();
        if (remainingNanos <= 0L) {
          return false;
        }
        long waitMillis = Math.max(1L, TimeUnit.NANOSECONDS.toMillis(remainingNanos));
        stateLock.wait(Math.min(waitMillis, PAUSE_POLL_MS));
      }
      return true;
    }
  }

  boolean isPrewarming() {
    synchronized (stateLock) {
      return !closed && active;
    }
  }

  void close() {
    ExecutorService executorToStop;
    Future<?> futureToCancel;
    synchronized (stateLock) {
      if (closed) {
        return;
      }
      closed = true;
      active = false;
      futureToCancel = future;
      executorToStop = executor;
      future = null;
      executor = null;
      stateLock.notifyAll();
    }
    if (futureToCancel != null) {
      futureToCancel.cancel(true);
    }
    if (executorToStop != null) {
      executorToStop.shutdownNow();
      ExecutorShutdown.shutdownAndAwait(executorToStop);
    }
  }

  private boolean needsOrRunningScanLocked() {
    if (active) {
      return true;
    }
    if (atCapacity) {
      return false;
    }
    Program program = session.currentProgramOrNull();
    if (program == null || Proxy.isProxyClass(program.getClass())) {
      return false;
    }
    long modNumber = program.getModificationNumber();
    if (!hasSyncedModification || syncedModificationNumber != modNumber) {
      return true;
    }
    return needsSnapshotRebuildLocked(program, modNumber);
  }

  private boolean needsSnapshotRebuildLocked(Program program, long modNumber) {
    return session.canCacheSnapshots()
        && !snapshotSkippedForSyncedMod
        && !owner.hasSymbolSnapshotFor(program, modNumber);
  }

  private void runLoop() {
    try {
      while (!closed && !Thread.currentThread().isInterrupted()) {
        Program program;
        long targetMod;
        boolean symbolsAlreadySynced;
        synchronized (stateLock) {
          while (!closed && !Thread.currentThread().isInterrupted()) {
            program = session.currentProgramOrNull();
            if (program == null || atCapacity || Proxy.isProxyClass(program.getClass())) {
              active = false;
              stateLock.notifyAll();
              stateLock.wait(PAUSE_POLL_MS);
              continue;
            }
            if (session.isPausedForPrewarm(program)) {
              active = false;
              stateLock.notifyAll();
              stateLock.wait(PAUSE_POLL_MS);
              continue;
            }
            targetMod = program.getModificationNumber();
            boolean modSynced = hasSyncedModification && syncedModificationNumber == targetMod;
            if (modSynced && !needsSnapshotRebuildLocked(program, targetMod)) {
              active = false;
              stateLock.notifyAll();
              stateLock.wait();
              continue;
            }
            active = true;
            break;
          }
          if (closed || Thread.currentThread().isInterrupted()) {
            return;
          }
          program = session.currentProgramOrNull();
          if (program == null || Proxy.isProxyClass(program.getClass())) {
            continue;
          }
          targetMod = program.getModificationNumber();
          symbolsAlreadySynced = hasSyncedModification && syncedModificationNumber == targetMod;
        }

        runSinglePass(program, targetMod, symbolsAlreadySynced);
      }
    } catch (InterruptedException ignored) {
      Thread.currentThread().interrupt();
    } finally {
      synchronized (stateLock) {
        active = false;
        stateLock.notifyAll();
      }
    }
  }

  private void runSinglePass(Program program, long initialMod, boolean symbolsAlreadySynced) {
    long passProgramEpoch = owner.programEpoch();
    long targetMod = initialMod;
    ScanCursor cursor = new ScanCursor();
    if (symbolsAlreadySynced && program.getModificationNumber() == initialMod) {
      cursor.finished = true;
    }

    while (!closed && !Thread.currentThread().isInterrupted() && !cursor.finished) {
      if (owner.programEpoch() != passProgramEpoch) {
        return;
      }
      if (cache.isAtCapacity()) {
        markAtCapacity();
        return;
      }
      if (session.isPausedForPrewarm(program)) {
        return;
      }
      if (program.getModificationNumber() != targetMod) {
        targetMod = program.getModificationNumber();
        cursor.reset();
      }

      final long expectedMod = targetMod;
      BatchOutcome outcome =
          session.tryCollectForPrewarm(
              program, () -> collectBatchLocked(program, expectedMod, cursor), BatchOutcome.PAUSED);
      if (outcome.status == BatchStatus.PAUSED) {
        return;
      }
      if (outcome.status == BatchStatus.MODIFIED) {
        targetMod = program.getModificationNumber();
        cursor.reset();
        continue;
      }

      for (SymbolSample sample : outcome.samples) {
        if (closed
            || Thread.currentThread().isInterrupted()
            || owner.programEpoch() != passProgramEpoch) {
          return;
        }
        if (cache.isAtCapacity()) {
          markAtCapacity();
          return;
        }
        if (session.isPausedForPrewarm(program)) {
          return;
        }
        if (!owner.prewarmSample(program, sample.name(), sample.address())) {
          if (owner.programEpoch() == passProgramEpoch && !closed && !Thread.currentThread().isInterrupted()) {
            markAtCapacity();
          }
          return;
        }
      }
    }

    if (closed
        || Thread.currentThread().isInterrupted()
        || !cursor.finished
        || owner.programEpoch() != passProgramEpoch) {
      return;
    }

    long snapshotEpoch = owner.invalidationEpoch();
    SymbolTableSnapshot.Outcome snapshotOutcome = owner.refreshSymbolSnapshot(program, targetMod);
    if (snapshotOutcome == SymbolTableSnapshot.Outcome.ABORTED
        || snapshotOutcome == SymbolTableSnapshot.Outcome.MODIFIED) {
      return;
    }

    final long syncedTargetMod = targetMod;
    Boolean stillUnmodified =
        session.tryCollectForPrewarm(
            program,
            () ->
                owner.programEpoch() == passProgramEpoch
                    && owner.invalidationEpoch() == snapshotEpoch
                    && program.getModificationNumber() == syncedTargetMod,
            null);
    if (!Boolean.TRUE.equals(stillUnmodified)) {
      return;
    }

    synchronized (stateLock) {
      if (!closed
          && !atCapacity
          && owner.programEpoch() == passProgramEpoch
          && owner.invalidationEpoch() == snapshotEpoch
          && program.getModificationNumber() == targetMod) {
        hasSyncedModification = true;
        syncedModificationNumber = targetMod;
        snapshotSkippedForSyncedMod =
            snapshotOutcome == SymbolTableSnapshot.Outcome.SKIPPED;
        fastSyncedMod = targetMod;
        active = false;
        stateLock.notifyAll();
      }
    }
  }

  private BatchOutcome collectBatchLocked(Program program, long expectedMod, ScanCursor cursor) {
    if (program.getModificationNumber() != expectedMod) {
      return BatchOutcome.MODIFIED;
    }
    SymbolTable symbolTable = program.getSymbolTable();
    List<SymbolSample> samples = new ArrayList<>(Math.min(config.batchSize(), 128));
    Set<String> seenInBatch = new HashSet<>();
    int scannedSteps = 0;

    while (cursor.prefixIndex < MANGLED_PREFIXES.length && samples.size() < config.batchSize()) {
      String prefix = MANGLED_PREFIXES[cursor.prefixIndex];
      String startKey = cursor.lastName != null ? cursor.lastName : prefix;
      String initialSkipName = cursor.lastName;
      SymbolIterator iterator;
      try {
        iterator = symbolTable.scanSymbolsByName(startKey);
      } catch (UnsupportedOperationException unsupported) {
        return collectFallbackBatchLocked(symbolTable, cursor, samples, seenInBatch);
      }
      if (iterator == null) {
        cursor.advancePrefix();
        continue;
      }

      boolean exhaustedPrefix = true;
      while (iterator.hasNext()) {
        Symbol symbol = iterator.next();
        if (symbol == null) {
          continue;
        }
        String name = symbol.getName();
        if (name == null || !name.startsWith(prefix)) {
          exhaustedPrefix = true;
          break;
        }
        if (initialSkipName != null && name.equals(initialSkipName)) {
          continue;
        }
        cursor.lastName = name;
        scannedSteps++;
        if (CppSymbolNames.isMangled(name)
            && !cache.contains(name)
            && seenInBatch.add(name)) {
          samples.add(new SymbolSample(name, symbol.getAddress()));
          if (samples.size() >= config.batchSize()) {
            exhaustedPrefix = false;
            break;
          }
        }
        if (scannedSteps >= SymbolTableSnapshot.MAX_SCAN_STEPS_PER_LOCK) {
          exhaustedPrefix = false;
          break;
        }
      }

      if (exhaustedPrefix) {
        cursor.advancePrefix();
      } else {
        break;
      }
    }

    if (cursor.prefixIndex >= MANGLED_PREFIXES.length) {
      cursor.finished = true;
    }
    return new BatchOutcome(BatchStatus.COLLECTED, samples);
  }

  private BatchOutcome collectFallbackBatchLocked(
      SymbolTable symbolTable,
      ScanCursor cursor,
      List<SymbolSample> samples,
      Set<String> seenInBatch) {
    SymbolIterator defined = symbolTable.getDefinedSymbols();
    if (defined != null) {
      while (defined.hasNext()) {
        Symbol symbol = defined.next();
        if (symbol == null) {
          continue;
        }
        String name = symbol.getName();
        if (CppSymbolNames.isMangled(name) && !cache.contains(name) && seenInBatch.add(name)) {
          samples.add(new SymbolSample(name, symbol.getAddress()));
        }
      }
    }
    cursor.prefixIndex = MANGLED_PREFIXES.length;
    cursor.finished = true;
    return new BatchOutcome(BatchStatus.COLLECTED, samples);
  }

  private enum BatchStatus {
    COLLECTED,
    PAUSED,
    MODIFIED
  }

  private static final class BatchOutcome {
    static final BatchOutcome PAUSED = new BatchOutcome(BatchStatus.PAUSED, List.of());
    static final BatchOutcome MODIFIED = new BatchOutcome(BatchStatus.MODIFIED, List.of());

    final BatchStatus status;
    final List<SymbolSample> samples;

    private BatchOutcome(BatchStatus status, List<SymbolSample> samples) {
      this.status = status;
      this.samples = samples;
    }
  }

  private static final class ScanCursor {
    int prefixIndex;
    String lastName;
    boolean finished;

    void advancePrefix() {
      prefixIndex++;
      lastName = null;
    }

    void reset() {
      prefixIndex = 0;
      lastName = null;
      finished = false;
    }
  }
}
