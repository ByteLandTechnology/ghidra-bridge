package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Session-owned, memory-bounded C++ demangle index with asynchronous batch pre-warming,
 * modification-number delta scans, and detached candidate metadata.
 */
public final class CppSymbolIndex implements AutoCloseable {
  private static final String[] MANGLED_PREFIXES = {"?", "_Z", "__Z"};
  private static final int MAX_SCAN_STEPS_PER_LOCK = 1024;
  private static final long PAUSE_POLL_MS = 25L;

  /** Pluggable demangler strategy (defaults to {@link DemanglerUtil#demangle}). */
  @FunctionalInterface
  public interface Demangler {
    List<DemangledObject> demangle(Program program, String name, Address address);
  }

  /** Memory and batching configuration for a session C++ symbol index. */
  public record Config(int maxEntries, long maxBytes, int batchSize) {
    public static final int DEFAULT_MAX_ENTRIES = 131_072;
    public static final long DEFAULT_MAX_BYTES = 64L * 1024L * 1024L;
    public static final int DEFAULT_BATCH_SIZE = 128;
    public static final String MAX_ENTRIES_PROPERTY = "ghidra.bridge.cppSymbolIndex.maxEntries";
    public static final String MAX_BYTES_PROPERTY = "ghidra.bridge.cppSymbolIndex.maxBytes";

    public Config {
      if (maxEntries < 1) {
        throw new IllegalArgumentException("maxEntries must be >= 1");
      }
      if (maxBytes < 256L) {
        throw new IllegalArgumentException("maxBytes must be >= 256");
      }
      if (batchSize < 1) {
        throw new IllegalArgumentException("batchSize must be >= 1");
      }
    }

    public static Config defaults() {
      int configuredEntries = readPositiveInt(MAX_ENTRIES_PROPERTY, DEFAULT_MAX_ENTRIES);
      long configuredBytes = readPositiveLong(MAX_BYTES_PROPERTY, DEFAULT_MAX_BYTES);
      return new Config(configuredEntries, Math.max(256L, configuredBytes), DEFAULT_BATCH_SIZE);
    }

    private static int readPositiveInt(String property, int fallback) {
      String raw = System.getProperty(property);
      if (raw == null || raw.isBlank()) return fallback;
      try {
        int parsed = Integer.parseInt(raw.trim());
        return parsed >= 1 ? parsed : fallback;
      } catch (NumberFormatException ignored) {
        return fallback;
      }
    }

    private static long readPositiveLong(String property, long fallback) {
      String raw = System.getProperty(property);
      if (raw == null || raw.isBlank()) return fallback;
      try {
        long parsed = Long.parseLong(raw.trim());
        return parsed >= 1L ? parsed : fallback;
      } catch (NumberFormatException ignored) {
        return fallback;
      }
    }
  }

  /** Detached candidate metadata for applying a demangled C++ name without retaining Program DB state. */
  public record Candidate(
      String mangled, String originalDemangled, String name, Demangled namespace) {
    static Candidate from(DemangledObject decoded) {
      return new Candidate(
          decoded.getMangledString(),
          decoded.getOriginalDemangled(),
          decoded.getName(),
          DetachedNamespace.from(decoded.getNamespace()));
    }
  }

  /** Immutable indexed demangle entry for a single mangled symbol string. */
  public record Entry(String demangledName, List<Candidate> candidates) {
    public static final Entry EMPTY = new Entry(null, List.of());

    public Entry {
      candidates = candidates == null ? List.of() : List.copyOf(candidates);
    }
  }

  /** Detached memory-symbol row ordered by {@code (address, id)} for fast {@code symbol.list} scans. */
  public record IndexedSymbol(
      long id,
      String idText,
      Address address,
      String canonicalAddress,
      String name,
      String namespace,
      String symbolType,
      String sourceType,
      boolean primary) {}

  /** Modification-tracked, immutable address-ordered memory-symbol snapshot. */
  public record SymbolSnapshot(
      Program program,
      long modificationNumber,
      AddressSpace singleAddressSpace,
      List<IndexedSymbol> symbols) {}

  private record CachedEntry(Entry entry, long bytes) {}

  private record SymbolSample(String name, Address address) {}

  private record RawSymbolRow(
      long id,
      Address address,
      String name,
      String namespace,
      String symbolType,
      String sourceType,
      boolean primary) {}

  private final GhidraSession session;
  private final Config config;
  private final Demangler demangler;

  private final Object cacheLock = new Object();
  private final LinkedHashMap<String, CachedEntry> entries =
      new LinkedHashMap<>(256, 0.75f, true);
  private final ConcurrentHashMap<String, CachedEntry> readView =
      new ConcurrentHashMap<>(256);
  private long usedBytes;
  private long snapshotBytes;
  private volatile SymbolSnapshot symbolSnapshot;
  private boolean closedForCache;
  private volatile boolean evictionActive;

  private final ConcurrentHashMap<String, CompletableFuture<Entry>> inFlight =
      new ConcurrentHashMap<>();

  private final Object stateLock = new Object();
  private ExecutorService prewarmExecutor;
  private Future<?> prewarmFuture;
  private boolean prewarmStarted;
  private boolean prewarmingActive;
  private boolean hasSyncedModification;
  private long syncedModificationNumber;
  private volatile long fastSyncedMod = Long.MIN_VALUE;
  private boolean prewarmAtCapacity;
  private volatile boolean closed;

  private final LongAdder hits = new LongAdder();
  private final LongAdder misses = new LongAdder();
  private final AtomicLong demangleCalls = new AtomicLong();

  public CppSymbolIndex(GhidraSession session) {
    this(session, Config.defaults(), DemanglerUtil::demangle);
  }

  public CppSymbolIndex(GhidraSession session, Config config, Demangler demangler) {
    this.session = Objects.requireNonNull(session, "session");
    this.config = Objects.requireNonNull(config, "config");
    this.demangler = Objects.requireNonNull(demangler, "demangler");
  }

  /** Starts asynchronous background pre-warming for the active session program if not yet started. */
  public void startPrewarm() {
    synchronized (stateLock) {
      if (closed || prewarmStarted) {
        return;
      }
      Program program = session.currentProgramOrNull();
      if (program == null) {
        return;
      }
      String programName = program.getName();
      if (programName == null || programName.isBlank()) {
        programName = "program";
      }
      final String threadSuffix = programName;
      prewarmStarted = true;
      prewarmingActive = true;
      prewarmExecutor =
          Executors.newSingleThreadExecutor(
              runnable -> {
                Thread thread = new Thread(runnable, "ghidra-cpp-index-" + threadSuffix);
                thread.setDaemon(true);
                return thread;
              });
      prewarmFuture = prewarmExecutor.submit(this::runPrewarmLoop);
    }
  }

  /** Returns the read-only demangled signature for {@code name}, or {@code null} if not mangled/supported. */
  public String demangled(Program program, String name, Address address) {
    return lookup(program, name, address).demangledName();
  }

  /**
   * Returns the indexed {@link Entry} (signature + detached candidates) for {@code name},
   * decoding and caching on demand if not yet present.
   */
  public Entry lookup(Program program, String name, Address address) {
    if (!CppSymbolNames.isMangled(name)) {
      return Entry.EMPTY;
    }
    Program target = program != null ? program : session.currentProgramOrNull();
    if (target == null) {
      return Entry.EMPTY;
    }
    observeProgramModification(target);

    CachedEntry hit = getCached(name);
    if (hit != null) {
      hits.increment();
      return hit.entry();
    }
    misses.increment();

    if (closed) {
      demangleCalls.incrementAndGet();
      return decode(demangler, target, name, address);
    }

    while (true) {
      CachedEntry recheck = getCached(name);
      if (recheck != null) {
        return recheck.entry();
      }
      CompletableFuture<Entry> ownFuture = new CompletableFuture<>();
      CompletableFuture<Entry> existing = inFlight.putIfAbsent(name, ownFuture);
      if (existing == null) {
        try {
          demangleCalls.incrementAndGet();
          Entry decoded = decode(demangler, target, name, address);
          putOnDemand(name, decoded);
          ownFuture.complete(decoded);
          return decoded;
        } catch (Throwable failure) {
          ownFuture.completeExceptionally(failure);
          throw failure;
        } finally {
          inFlight.remove(name, ownFuture);
        }
      }
      try {
        return existing.join();
      } catch (CompletionException completion) {
        if (completion.getCause() instanceof PrewarmAbortedException) {
          // Background pre-warming yielded or stopped; retry on the foreground thread.
          continue;
        }
        if (completion.getCause() instanceof RuntimeException runtimeException) {
          throw runtimeException;
        }
        if (completion.getCause() instanceof Error error) {
          throw error;
        }
        throw completion;
      }
    }
  }

  /** Returns true when a full pre-warm pass has completed for the current program modification. */
  public boolean isSyncedWithProgram(Program program) {
    if (program == null || closed) {
      return false;
    }
    long modNumber = program.getModificationNumber();
    synchronized (stateLock) {
      return !closed
          && !prewarmAtCapacity
          && hasSyncedModification
          && syncedModificationNumber == modNumber;
    }
  }

  /** Ensures {@code name} is decoded into the index outside {@code executionLock} without counting a read hit. */
  public void warmOnDemand(Program program, String name, Address address) {
    if (!CppSymbolNames.isMangled(name) || closed) {
      return;
    }
    Program target = program != null ? program : session.currentProgramOrNull();
    if (target == null || containsCached(name)) {
      return;
    }
    CompletableFuture<Entry> ownFuture = new CompletableFuture<>();
    CompletableFuture<Entry> existing = inFlight.putIfAbsent(name, ownFuture);
    if (existing != null) {
      try {
        existing.join();
      } catch (CompletionException ignored) {
        // Foreground lookup inside lookup() will retry if needed.
      }
      return;
    }
    try {
      if (!containsCached(name)) {
        demangleCalls.incrementAndGet();
        Entry decoded = decode(demangler, target, name, address);
        putOnDemand(name, decoded);
        ownFuture.complete(decoded);
      } else {
        CachedEntry hit = getCached(name);
        ownFuture.complete(hit != null ? hit.entry() : Entry.EMPTY);
      }
    } catch (Throwable failure) {
      ownFuture.completeExceptionally(failure);
      throw failure;
    } finally {
      inFlight.remove(name, ownFuture);
    }
  }

  /** Wakes the background pre-warmer when a transaction, command, or analysis changes state. */
  void onSessionStateChanged() {
    synchronized (stateLock) {
      if (!closed && prewarmStarted) {
        stateLock.notifyAll();
      }
    }
  }

  /**
   * Returns the pre-warmed address-ordered {@link SymbolSnapshot} if valid for {@code program}'s
   * current {@code modificationNumber} and {@code iterationStart}'s memory address space.
   */
  public SymbolSnapshot symbolSnapshotIfCurrent(Program program, Address iterationStart) {
    if (closed
        || program == null
        || iterationStart == null
        || !iterationStart.isMemoryAddress()) {
      return null;
    }
    long modNumber = program.getModificationNumber();
    SymbolSnapshot current = symbolSnapshot;
    if (current != null
        && current.program() == program
        && current.modificationNumber() == modNumber
        && (current.singleAddressSpace() == null
            || current.singleAddressSpace().equals(iterationStart.getAddressSpace()))) {
      return current;
    }
    observeProgramModification(program);
    return null;
  }

  /** Waits until the current pre-warming pass reaches quiescence or the timeout elapses. */
  public boolean awaitPrewarm(Duration timeout) throws InterruptedException {
    Objects.requireNonNull(timeout, "timeout");
    long deadlineNanos = System.nanoTime() + Math.max(0L, timeout.toNanos());
    synchronized (stateLock) {
      while (!closed && prewarmStarted && needsOrRunningScanLocked()) {
        if (!prewarmingActive) {
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

  public boolean isPrewarming() {
    synchronized (stateLock) {
      return !closed && prewarmingActive;
    }
  }

  public long hits() {
    return hits.sum();
  }

  public long misses() {
    return misses.sum();
  }

  public long demangleCalls() {
    return demangleCalls.get();
  }

  public int entryCount() {
    synchronized (cacheLock) {
      return entries.size();
    }
  }

  public long estimatedBytes() {
    synchronized (cacheLock) {
      return usedBytes;
    }
  }

  public Config config() {
    return config;
  }

  @Override
  public void close() {
    ExecutorService executorToStop;
    Future<?> futureToCancel;
    synchronized (stateLock) {
      if (closed) {
        clearCache();
        return;
      }
      closed = true;
      prewarmingActive = false;
      futureToCancel = prewarmFuture;
      executorToStop = prewarmExecutor;
      prewarmFuture = null;
      prewarmExecutor = null;
      stateLock.notifyAll();
    }
    if (futureToCancel != null) {
      futureToCancel.cancel(true);
    }
    clearCache();
    if (executorToStop != null) {
      shutdownAndAwaitNow(executorToStop);
    }
    inFlight.clear();
    clearCache();
  }

  static Entry decode(Demangler demangler, Program program, String name, Address address) {
    List<DemangledObject> objects = demangler.demangle(program, name, address);
    if (objects == null || objects.isEmpty()) {
      return Entry.EMPTY;
    }
    String signature = null;
    List<Candidate> candidates = new ArrayList<>(objects.size());
    for (DemangledObject object : objects) {
      if (object == null) {
        continue;
      }
      if (signature == null) {
        String candidateSignature = object.getSignature(false);
        if (candidateSignature != null
            && !candidateSignature.isBlank()
            && !candidateSignature.equals(name)) {
          signature = candidateSignature;
        }
      }
      candidates.add(Candidate.from(object));
    }
    if (signature == null && candidates.isEmpty()) {
      return Entry.EMPTY;
    }
    return new Entry(signature, candidates);
  }

  private void observeProgramModification(Program program) {
    if (closed || evictionActive) {
      return;
    }
    long modNumber = program.getModificationNumber();
    if (modNumber == fastSyncedMod) {
      return;
    }
    synchronized (stateLock) {
      if (closed || !prewarmStarted || prewarmAtCapacity) {
        return;
      }
      if (!hasSyncedModification || syncedModificationNumber != modNumber) {
        stateLock.notifyAll();
      }
    }
  }

  private boolean needsOrRunningScanLocked() {
    if (prewarmingActive) {
      return true;
    }
    if (prewarmAtCapacity) {
      return false;
    }
    Program program = session.currentProgramOrNull();
    if (program == null) {
      return false;
    }
    return !hasSyncedModification || syncedModificationNumber != program.getModificationNumber();
  }

  private void runPrewarmLoop() {
    try {
      while (!closed && !Thread.currentThread().isInterrupted()) {
        Program program;
        long targetMod;
        synchronized (stateLock) {
          while (!closed && !Thread.currentThread().isInterrupted()) {
            program = session.currentProgramOrNull();
            if (program == null || prewarmAtCapacity) {
              prewarmingActive = false;
              stateLock.notifyAll();
              stateLock.wait(PAUSE_POLL_MS);
              continue;
            }
            if (session.isPausedForPrewarm(program)) {
              prewarmingActive = false;
              stateLock.notifyAll();
              stateLock.wait(PAUSE_POLL_MS);
              continue;
            }
            targetMod = program.getModificationNumber();
            if (hasSyncedModification && syncedModificationNumber == targetMod) {
              prewarmingActive = false;
              stateLock.notifyAll();
              stateLock.wait();
              continue;
            }
            prewarmingActive = true;
            break;
          }
          if (closed || Thread.currentThread().isInterrupted()) {
            return;
          }
          program = session.currentProgramOrNull();
          if (program == null) {
            continue;
          }
          targetMod = program.getModificationNumber();
        }

        runSinglePass(program, targetMod);
      }
    } catch (InterruptedException ignored) {
      Thread.currentThread().interrupt();
    } finally {
      synchronized (stateLock) {
        prewarmingActive = false;
        stateLock.notifyAll();
      }
    }
  }

  private void runSinglePass(Program program, long initialMod) throws InterruptedException {
    long targetMod = initialMod;
    ScanCursor cursor = new ScanCursor();

    while (!closed && !Thread.currentThread().isInterrupted() && !cursor.finished) {
      if (isCacheAtCapacity()) {
        markPrewarmAtCapacity();
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
        if (closed || Thread.currentThread().isInterrupted()) {
          return;
        }
        if (isCacheAtCapacity()) {
          markPrewarmAtCapacity();
          return;
        }
        if (session.isPausedForPrewarm(program)) {
          return;
        }
        if (!prewarmSample(program, sample)) {
          markPrewarmAtCapacity();
          return;
        }
      }
    }

    if (closed || Thread.currentThread().isInterrupted() || !cursor.finished) {
      return;
    }

    SymbolSnapshotOutcome snapshotOutcome = buildSymbolSnapshot(program, targetMod);
    if (snapshotOutcome == SymbolSnapshotOutcome.ABORTED) {
      return;
    }
    if (snapshotOutcome == SymbolSnapshotOutcome.MODIFIED) {
      // Program mutated while building the symbol snapshot; outer loop will immediately re-sync.
      return;
    }

    synchronized (stateLock) {
      if (!closed && !prewarmAtCapacity && program.getModificationNumber() == targetMod) {
        hasSyncedModification = true;
        syncedModificationNumber = targetMod;
        fastSyncedMod = targetMod;
        prewarmingActive = false;
        stateLock.notifyAll();
      }
    }
  }

  private boolean prewarmSample(Program program, SymbolSample sample) {
    if (containsCached(sample.name())) {
      return true;
    }
    CompletableFuture<Entry> ownFuture = new CompletableFuture<>();
    CompletableFuture<Entry> existing = inFlight.putIfAbsent(sample.name(), ownFuture);
    if (existing != null) {
      return true;
    }
    boolean completed = false;
    try {
      if (containsCached(sample.name())) {
        CachedEntry hit = getCached(sample.name());
        ownFuture.complete(hit != null ? hit.entry() : Entry.EMPTY);
        completed = true;
        return true;
      }
      demangleCalls.incrementAndGet();
      Entry decoded = decode(demangler, program, sample.name(), sample.address());
      if (closed || Thread.currentThread().isInterrupted()) {
        ownFuture.completeExceptionally(new PrewarmAbortedException());
        completed = true;
        return false;
      }
      boolean fitted = putFromPrewarm(sample.name(), decoded);
      ownFuture.complete(decoded);
      completed = true;
      return fitted;
    } catch (Throwable failure) {
      if (!completed) {
        if (closed || Thread.currentThread().isInterrupted()) {
          ownFuture.completeExceptionally(new PrewarmAbortedException());
        } else {
          ownFuture.completeExceptionally(failure);
        }
      }
      if (closed || Thread.currentThread().isInterrupted()) {
        return false;
      }
      throw failure;
    } finally {
      inFlight.remove(sample.name(), ownFuture);
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
            && !containsCached(name)
            && seenInBatch.add(name)) {
          samples.add(new SymbolSample(name, symbol.getAddress()));
          if (samples.size() >= config.batchSize()) {
            exhaustedPrefix = false;
            break;
          }
        }
        if (scannedSteps >= MAX_SCAN_STEPS_PER_LOCK) {
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
        if (CppSymbolNames.isMangled(name) && !containsCached(name) && seenInBatch.add(name)) {
          samples.add(new SymbolSample(name, symbol.getAddress()));
        }
      }
    }
    cursor.prefixIndex = MANGLED_PREFIXES.length;
    cursor.finished = true;
    return new BatchOutcome(BatchStatus.COLLECTED, samples);
  }

  private SymbolSnapshotOutcome buildSymbolSnapshot(Program program, long expectedMod) {
    SnapshotCursor cursor = new SnapshotCursor();
    IdentityHashMap<Namespace, String> namespaceNames = new IdentityHashMap<>();
    HashMap<String, String> sharedStrings = new HashMap<>(64);
    List<IndexedSymbol> built = new ArrayList<>(256);
    long runningBytes = 64L;

    while (!closed && !Thread.currentThread().isInterrupted() && !cursor.finished) {
      if (session.isPausedForPrewarm(program)) {
        return SymbolSnapshotOutcome.ABORTED;
      }
      if (program.getModificationNumber() != expectedMod) {
        dropSnapshot();
        return SymbolSnapshotOutcome.MODIFIED;
      }

      SnapshotBatch batch =
          session.tryCollectForPrewarm(
              program,
              () ->
                  collectSnapshotBatchLocked(
                      program, expectedMod, cursor, namespaceNames, sharedStrings),
              SnapshotBatch.PAUSED);
      if (batch.status == BatchStatus.PAUSED) {
        return SymbolSnapshotOutcome.ABORTED;
      }
      if (batch.status == BatchStatus.MODIFIED) {
        dropSnapshot();
        return SymbolSnapshotOutcome.MODIFIED;
      }
      if (!cursor.supported) {
        dropSnapshot();
        return SymbolSnapshotOutcome.SKIPPED;
      }

      for (RawSymbolRow raw : batch.rows) {
        if (closed || Thread.currentThread().isInterrupted()) {
          return SymbolSnapshotOutcome.ABORTED;
        }
        if (built.size() + 1 > config.maxEntries()) {
          dropSnapshot();
          return SymbolSnapshotOutcome.SKIPPED;
        }
        String canonicalAddress = AddressUtil.canonicalAddress(raw.address());
        String idText = Long.toString(raw.id());
        long rowBytes =
            56L
                + stringBytes(canonicalAddress)
                + stringBytes(idText)
                + (containsCached(raw.name()) ? 0L : stringBytes(raw.name()));
        runningBytes += rowBytes;
        if (!fitsSnapshotBudget(runningBytes)) {
          dropSnapshot();
          return SymbolSnapshotOutcome.SKIPPED;
        }
        built.add(
            new IndexedSymbol(
                raw.id(),
                idText,
                raw.address(),
                canonicalAddress,
                raw.name(),
                raw.namespace(),
                raw.symbolType(),
                raw.sourceType(),
                raw.primary()));
      }
    }

    if (closed || Thread.currentThread().isInterrupted() || !cursor.finished) {
      return SymbolSnapshotOutcome.ABORTED;
    }
    if (program.getModificationNumber() != expectedMod) {
      dropSnapshot();
      return SymbolSnapshotOutcome.MODIFIED;
    }
    publishSnapshot(
        new SymbolSnapshot(program, expectedMod, cursor.singleSpace, List.copyOf(built)),
        runningBytes);
    return SymbolSnapshotOutcome.BUILT;
  }

  private static SnapshotBatch collectSnapshotBatchLocked(
      Program program,
      long expectedMod,
      SnapshotCursor cursor,
      IdentityHashMap<Namespace, String> namespaceNames,
      HashMap<String, String> sharedStrings) {
    if (program.getModificationNumber() != expectedMod) {
      return SnapshotBatch.MODIFIED;
    }
    SymbolTable symbolTable = program.getSymbolTable();
    SymbolIterator iterator;
    try {
      iterator =
          cursor.lastAddress == null
              ? symbolTable.getSymbolIterator(true)
              : symbolTable.getSymbolIterator(cursor.lastAddress, true);
    } catch (RuntimeException unsupported) {
      cursor.supported = false;
      cursor.finished = true;
      return SnapshotBatch.EMPTY;
    }
    if (iterator == null) {
      cursor.finished = true;
      return SnapshotBatch.EMPTY;
    }

    List<RawSymbolRow> rows = new ArrayList<>(Math.min(MAX_SCAN_STEPS_PER_LOCK, 256));
    int steps = 0;
    boolean exhausted = true;
    while (iterator.hasNext()) {
      Symbol symbol = iterator.next();
      if (symbol == null) {
        continue;
      }
      Address address = symbol.getAddress();
      if (address == null || !address.isMemoryAddress()) {
        cursor.supported = false;
        cursor.finished = true;
        return SnapshotBatch.EMPTY;
      }
      AddressSpace space = address.getAddressSpace();
      if (cursor.singleSpace == null) {
        cursor.singleSpace = space;
      } else if (!cursor.singleSpace.equals(space)) {
        cursor.supported = false;
        cursor.finished = true;
        return SnapshotBatch.EMPTY;
      }
      long id = symbol.getID();
      if (cursor.lastAddress != null) {
        int byAddr = address.compareTo(cursor.lastAddress);
        if (byAddr < 0 || (byAddr == 0 && id <= cursor.lastId)) {
          if (cursor.resumingFromPreviousBatch && byAddr == 0 && id <= cursor.lastId) {
            continue;
          }
          cursor.supported = false;
          cursor.finished = true;
          return SnapshotBatch.EMPTY;
        }
        cursor.resumingFromPreviousBatch = false;
      }
      cursor.lastAddress = address;
      cursor.lastId = id;

      Namespace parent = symbol.getParentNamespace();
      String nsName = null;
      if (parent != null) {
        nsName = namespaceNames.get(parent);
        if (nsName == null) {
          String computed = parent.getName(true);
          nsName = computed == null ? null : sharedStrings.computeIfAbsent(computed, k -> k);
          if (nsName != null) {
            namespaceNames.put(parent, nsName);
          }
        }
      }
      String typeText =
          symbol.getSymbolType() == null
              ? null
              : sharedStrings.computeIfAbsent(symbol.getSymbolType().toString(), k -> k);
      String rawSource = String.valueOf(symbol.getSource());
      String sourceText = sharedStrings.computeIfAbsent(rawSource, k -> k);

      rows.add(
          new RawSymbolRow(
              id, address, symbol.getName(), nsName, typeText, sourceText, symbol.isPrimary()));
      steps++;
      if (steps >= MAX_SCAN_STEPS_PER_LOCK) {
        cursor.resumingFromPreviousBatch = true;
        exhausted = false;
        break;
      }
    }
    if (exhausted) {
      cursor.finished = true;
    }
    return new SnapshotBatch(BatchStatus.COLLECTED, rows);
  }

  private boolean fitsSnapshotBudget(long candidateSnapshotBytes) {
    synchronized (cacheLock) {
      if (closedForCache) {
        return false;
      }
      long cppOnlyBytes = usedBytes - snapshotBytes;
      return cppOnlyBytes + candidateSnapshotBytes <= config.maxBytes();
    }
  }

  private void publishSnapshot(SymbolSnapshot snapshot, long bytes) {
    synchronized (cacheLock) {
      if (closedForCache) {
        return;
      }
      long cppOnlyBytes = usedBytes - snapshotBytes;
      if (cppOnlyBytes + bytes > config.maxBytes()
          || snapshot.symbols().size() > config.maxEntries()) {
        usedBytes = cppOnlyBytes;
        snapshotBytes = 0L;
        symbolSnapshot = null;
        return;
      }
      usedBytes = cppOnlyBytes + bytes;
      snapshotBytes = bytes;
      symbolSnapshot = snapshot;
    }
  }

  private void dropSnapshot() {
    synchronized (cacheLock) {
      if (snapshotBytes != 0L || symbolSnapshot != null) {
        usedBytes = Math.max(0L, usedBytes - snapshotBytes);
        snapshotBytes = 0L;
        symbolSnapshot = null;
      }
    }
  }

  private CachedEntry getCached(String name) {
    if (closed) {
      return null;
    }
    if (!evictionActive) {
      return readView.get(name);
    }
    synchronized (cacheLock) {
      if (closedForCache) {
        return null;
      }
      return entries.get(name);
    }
  }

  private boolean containsCached(String name) {
    if (closed) {
      return false;
    }
    return readView.containsKey(name);
  }

  private boolean isCacheAtCapacity() {
    synchronized (cacheLock) {
      return closedForCache
          || entries.size() >= config.maxEntries()
          || usedBytes >= config.maxBytes();
    }
  }

  private void markPrewarmAtCapacity() {
    evictionActive = true;
    synchronized (stateLock) {
      prewarmAtCapacity = true;
      prewarmingActive = false;
      stateLock.notifyAll();
    }
  }

  private boolean putFromPrewarm(String name, Entry entry) {
    long entryBytes = estimateEntryBytes(name, entry);
    synchronized (cacheLock) {
      if (closedForCache) {
        return false;
      }
      if (entries.containsKey(name)) {
        return true;
      }
      if (entries.size() >= config.maxEntries() || usedBytes + entryBytes > config.maxBytes()) {
        return false;
      }
      CachedEntry cached = new CachedEntry(entry, entryBytes);
      entries.put(name, cached);
      readView.put(name, cached);
      usedBytes += entryBytes;
      return entries.size() < config.maxEntries() && usedBytes < config.maxBytes();
    }
  }

  private void putOnDemand(String name, Entry entry) {
    long entryBytes = estimateEntryBytes(name, entry);
    if (entryBytes > config.maxBytes()) {
      return;
    }
    boolean freedSpace = false;
    synchronized (cacheLock) {
      if (closedForCache) {
        return;
      }
      CachedEntry previous = entries.remove(name);
      if (previous != null) {
        readView.remove(name);
        usedBytes -= previous.bytes();
      }
      if (symbolSnapshot != null && usedBytes + entryBytes > config.maxBytes()) {
        usedBytes = Math.max(0L, usedBytes - snapshotBytes);
        snapshotBytes = 0L;
        symbolSnapshot = null;
      }
      Iterator<Map.Entry<String, CachedEntry>> iterator = entries.entrySet().iterator();
      while (iterator.hasNext()
          && (entries.size() >= config.maxEntries()
              || usedBytes + entryBytes > config.maxBytes())) {
        Map.Entry<String, CachedEntry> eldest = iterator.next();
        CachedEntry evicted = eldest.getValue();
        readView.remove(eldest.getKey());
        iterator.remove();
        usedBytes -= evicted.bytes();
        freedSpace = true;
      }
      if (freedSpace) {
        evictionActive = true;
      }
      CachedEntry cached = new CachedEntry(entry, entryBytes);
      entries.put(name, cached);
      readView.put(name, cached);
      usedBytes += entryBytes;
    }
    if (freedSpace) {
      synchronized (stateLock) {
        // Keep prewarmAtCapacity set so background pre-warming does not re-evict foreground entries.
        prewarmAtCapacity = true;
      }
    }
  }

  private void clearCache() {
    synchronized (cacheLock) {
      closedForCache = true;
      entries.clear();
      readView.clear();
      symbolSnapshot = null;
      snapshotBytes = 0L;
      usedBytes = 0L;
    }
  }

  static long estimateEntryBytes(String key, Entry entry) {
    long total = 96L + stringBytes(key) + stringBytes(entry.demangledName());
    for (Candidate candidate : entry.candidates()) {
      total +=
          48L
              + stringBytes(candidate.mangled())
              + stringBytes(candidate.originalDemangled())
              + stringBytes(candidate.name())
              + namespaceBytes(candidate.namespace());
    }
    return Math.max(64L, total);
  }

  private static long stringBytes(String text) {
    return text == null ? 0L : 40L + (2L * text.length());
  }

  private static long namespaceBytes(Demangled namespace) {
    long total = 0L;
    for (Demangled cursor = namespace; cursor != null; cursor = cursor.getNamespace()) {
      total += 32L + stringBytes(cursor.getNamespaceName());
    }
    return total;
  }

  private static void shutdownAndAwaitNow(ExecutorService executor) {
    executor.shutdownNow();
    boolean interrupted = Thread.interrupted();
    try {
      executor.awaitTermination(5, TimeUnit.SECONDS);
    } catch (InterruptedException ex) {
      interrupted = true;
      executor.shutdownNow();
    } finally {
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private enum BatchStatus {
    COLLECTED,
    PAUSED,
    MODIFIED
  }

  static final class BatchOutcome {
    static final BatchOutcome PAUSED = new BatchOutcome(BatchStatus.PAUSED, List.of());
    static final BatchOutcome MODIFIED = new BatchOutcome(BatchStatus.MODIFIED, List.of());

    final BatchStatus status;
    final List<SymbolSample> samples;

    private BatchOutcome(BatchStatus status, List<SymbolSample> samples) {
      this.status = status;
      this.samples = samples;
    }
  }

  private enum SymbolSnapshotOutcome {
    BUILT,
    SKIPPED,
    MODIFIED,
    ABORTED
  }

  private static final class SnapshotBatch {
    static final SnapshotBatch PAUSED = new SnapshotBatch(BatchStatus.PAUSED, List.of());
    static final SnapshotBatch MODIFIED = new SnapshotBatch(BatchStatus.MODIFIED, List.of());
    static final SnapshotBatch EMPTY = new SnapshotBatch(BatchStatus.COLLECTED, List.of());

    final BatchStatus status;
    final List<RawSymbolRow> rows;

    private SnapshotBatch(BatchStatus status, List<RawSymbolRow> rows) {
      this.status = status;
      this.rows = rows;
    }
  }

  private static final class SnapshotCursor {
    AddressSpace singleSpace;
    Address lastAddress;
    long lastId;
    boolean resumingFromPreviousBatch;
    boolean supported = true;
    boolean finished;
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

  private static final class PrewarmAbortedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    @Override
    public Throwable fillInStackTrace() {
      return this;
    }
  }

  /** Immutable namespace chain detached from {@link ghidra.app.util.demangler.MangledContext}. */
  private record DetachedNamespace(String namespaceName, DetachedNamespace parent)
      implements Demangled {
    static DetachedNamespace from(Demangled source) {
      if (source == null) {
        return null;
      }
      List<String> names = new ArrayList<>(4);
      for (Demangled cursor = source; cursor != null; cursor = cursor.getNamespace()) {
        names.add(cursor.getNamespaceName());
      }
      DetachedNamespace built = null;
      for (int i = names.size() - 1; i >= 0; i--) {
        built = new DetachedNamespace(names.get(i), built);
      }
      return built;
    }

    @Override
    public String getMangledString() {
      return null;
    }

    @Override
    public String getOriginalDemangled() {
      return null;
    }

    @Override
    public String getName() {
      return namespaceName;
    }

    @Override
    public void setName(String name) {
      throw new UnsupportedOperationException("DetachedNamespace is immutable");
    }

    @Override
    public String getDemangledName() {
      return namespaceName;
    }

    @Override
    public Demangled getNamespace() {
      return parent;
    }

    @Override
    public void setNamespace(Demangled ns) {
      throw new UnsupportedOperationException("DetachedNamespace is immutable");
    }

    @Override
    public String getNamespaceName() {
      return namespaceName;
    }

    @Override
    public String getNamespaceString() {
      if (parent == null) {
        return namespaceName;
      }
      StringBuilder builder = new StringBuilder();
      appendNamespaceString(builder, this);
      return builder.toString();
    }

    @Override
    public String getSignature() {
      return getNamespaceString();
    }

    private static void appendNamespaceString(StringBuilder builder, DetachedNamespace node) {
      List<String> parts = new ArrayList<>(4);
      for (DetachedNamespace cursor = node; cursor != null; cursor = cursor.parent) {
        parts.add(cursor.namespaceName);
      }
      for (int i = parts.size() - 1; i >= 0; i--) {
        if (i < parts.size() - 1) {
          builder.append("::");
        }
        builder.append(parts.get(i));
      }
    }
  }
}
