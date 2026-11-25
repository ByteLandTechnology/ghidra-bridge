package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.DecodedSymbol;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.io.Serial;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Coordinates session-owned C++ symbol decoding, bounded caching, and background pre-warming.
 */
public final class CppSymbolIndex implements AutoCloseable {
  private final GhidraSession session;
  private final CppSymbolIndexConfig config;
  private final CppDemangler demangler;
  private final boolean shareStaticCache;
  private final CppSymbolCache cache;
  private final CppSymbolPrewarmer prewarmer;
  private final ConcurrentHashMap<String, CompletableFuture<DecodedSymbol>> inFlight =
      new ConcurrentHashMap<>();
  private volatile SymbolTableSnapshot symbolSnapshot;
  private volatile boolean closed;

  private final LongAdder hits = new LongAdder();
  private final LongAdder misses = new LongAdder();
  private final AtomicLong demangleCalls = new AtomicLong();

  public CppSymbolIndex(GhidraSession session) {
    this(session, CppSymbolIndexConfig.defaults(), DemanglerUtil::demangle, true);
  }

  public CppSymbolIndex(
      GhidraSession session, CppSymbolIndexConfig config, CppDemangler demangler) {
    this(session, config, demangler, false);
  }

  private CppSymbolIndex(
      GhidraSession session,
      CppSymbolIndexConfig config,
      CppDemangler demangler,
      boolean shareStaticCache) {
    this.session = Objects.requireNonNull(session, "session");
    this.config = Objects.requireNonNull(config, "config");
    this.demangler = Objects.requireNonNull(demangler, "demangler");
    this.shareStaticCache = shareStaticCache;
    this.cache = new CppSymbolCache(config);
    this.prewarmer = new CppSymbolPrewarmer(session, config, cache, this);
  }

  /** Starts asynchronous background pre-warming for the active session program. */
  public void startPrewarm() {
    prewarmer.start();
  }

  /** Returns the demangled signature for {@code name}, or {@code null} when unsupported. */
  public String demangled(Program program, String name, Address address) {
    return lookup(program, name, address).signature();
  }

  /** Returns the decoded symbol entry for {@code name}, decoding on demand on a cache miss. */
  public DecodedSymbol lookup(Program program, String name, Address address) {
    if (!CppSymbolNames.isMangled(name)) {
      return DecodedSymbol.EMPTY;
    }
    Program target = program != null ? program : session.currentProgramOrNull();
    if (target == null) {
      return DecodedSymbol.EMPTY;
    }
    prewarmer.observeProgramModification(target, cache.isEvictionActive());

    DecodedSymbol hit = closed ? null : cache.get(name);
    if (hit != null) {
      hits.increment();
      return hit;
    }
    if (!closed && shareStaticCache) {
      DecodedSymbol staticHit = CppSymbolNames.peekCached(target, name);
      if (staticHit != null) {
        storeOnDemand(name, staticHit);
        hits.increment();
        return staticHit;
      }
    }
    misses.increment();

    if (closed) {
      demangleCalls.incrementAndGet();
      return CppSymbolNames.decodeWith(demangler, target, name, address);
    }

    while (true) {
      DecodedSymbol recheck = cache.get(name);
      if (recheck != null) {
        return recheck;
      }
      CompletableFuture<DecodedSymbol> ownFuture = new CompletableFuture<>();
      CompletableFuture<DecodedSymbol> existing = inFlight.putIfAbsent(name, ownFuture);
      if (existing == null) {
        try {
          demangleCalls.incrementAndGet();
          DecodedSymbol decoded = CppSymbolNames.decodeWith(demangler, target, name, address);
          storeOnDemand(name, decoded);
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

  /** Decodes {@code name} into the index outside {@code executionLock} without counting a read hit. */
  public void warmOnDemand(Program program, String name, Address address) {
    if (!CppSymbolNames.isMangled(name) || closed) {
      return;
    }
    Program target = program != null ? program : session.currentProgramOrNull();
    if (target == null || cache.contains(name)) {
      return;
    }
    if (shareStaticCache) {
      DecodedSymbol staticHit = CppSymbolNames.peekCached(target, name);
      if (staticHit != null) {
        storeOnDemand(name, staticHit);
        return;
      }
    }
    CompletableFuture<DecodedSymbol> ownFuture = new CompletableFuture<>();
    CompletableFuture<DecodedSymbol> existing = inFlight.putIfAbsent(name, ownFuture);
    if (existing != null) {
      try {
        existing.join();
      } catch (CompletionException ignored) {
        // Subsequent lookup() retries if background pre-warming aborted.
      }
      return;
    }
    try {
      DecodedSymbol existingHit = cache.get(name);
      if (existingHit == null) {
        demangleCalls.incrementAndGet();
        DecodedSymbol decoded = CppSymbolNames.decodeWith(demangler, target, name, address);
        storeOnDemand(name, decoded);
        ownFuture.complete(decoded);
      } else {
        ownFuture.complete(existingHit);
      }
    } catch (Throwable failure) {
      ownFuture.completeExceptionally(failure);
      throw failure;
    } finally {
      inFlight.remove(name, ownFuture);
    }
  }

  public boolean isSyncedWithProgram(Program program) {
    return prewarmer.isSyncedWithProgram(program);
  }

  public SymbolTableSnapshot symbolSnapshotIfCurrent(Program program, Address iterationStart) {
    if (closed) {
      return null;
    }
    SymbolTableSnapshot current = symbolSnapshot;
    if (current != null && current.isCurrentFor(session, program, iterationStart)) {
      return current;
    }
    prewarmer.observeProgramModification(program, cache.isEvictionActive());
    return null;
  }

  public boolean awaitPrewarm(Duration timeout) throws InterruptedException {
    return prewarmer.awaitQuiescence(timeout);
  }

  public boolean isPrewarming() {
    return prewarmer.isPrewarming();
  }

  public boolean isClosed() {
    return closed;
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
    return cache.entryCount();
  }

  public long estimatedBytes() {
    return cache.estimatedBytes();
  }

  public CppSymbolIndexConfig config() {
    return config;
  }

  @Override
  public void close() {
    closed = true;
    prewarmer.close();
    symbolSnapshot = null;
    cache.close();
    inFlight.clear();
  }

  void invalidateSnapshots() {
    symbolSnapshot = null;
    cache.releaseSnapshotBytes();
  }

  void resetForProgramSwitch() {
    symbolSnapshot = null;
    cache.reset();
    inFlight.clear();
    prewarmer.resetForProgramSwitch();
  }

  void onSessionStateChanged() {
    prewarmer.onStateChanged();
  }

  boolean prewarmSample(Program program, String name, Address address) {
    if (cache.contains(name)) {
      return true;
    }
    if (shareStaticCache) {
      DecodedSymbol staticHit = CppSymbolNames.peekCached(program, name);
      if (staticHit != null) {
        return cache.putFromPrewarm(name, staticHit);
      }
    }
    CompletableFuture<DecodedSymbol> ownFuture = new CompletableFuture<>();
    CompletableFuture<DecodedSymbol> existing = inFlight.putIfAbsent(name, ownFuture);
    if (existing != null) {
      return true;
    }
    boolean completed = false;
    try {
      DecodedSymbol alreadyCached = cache.get(name);
      if (alreadyCached != null) {
        ownFuture.complete(alreadyCached);
        completed = true;
        return true;
      }
      demangleCalls.incrementAndGet();
      DecodedSymbol decoded = CppSymbolNames.decodeWith(demangler, program, name, address);
      if (closed || Thread.currentThread().isInterrupted()) {
        ownFuture.completeExceptionally(new PrewarmAbortedException());
        completed = true;
        return false;
      }
      boolean fitted = cache.putFromPrewarm(name, decoded);
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
      inFlight.remove(name, ownFuture);
    }
  }

  SymbolTableSnapshot.Outcome refreshSymbolSnapshot(Program program, long expectedMod) {
    return SymbolTableSnapshot.build(
        session,
        program,
        expectedMod,
        config,
        cache,
        () -> closed || Thread.currentThread().isInterrupted(),
        built -> symbolSnapshot = built,
        this::invalidateSnapshots);
  }

  private void storeOnDemand(String name, DecodedSymbol symbol) {
    if (cache.putOnDemand(name, symbol, () -> symbolSnapshot = null)) {
      prewarmer.markAtCapacity();
    }
  }

  private static final class PrewarmAbortedException extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;

    @Override
    public Throwable fillInStackTrace() {
      return this;
    }
  }
}
