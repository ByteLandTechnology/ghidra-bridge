package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Shares bounded {@link DecompInterface} pools across session services. */
public final class DecompilerPool implements AutoCloseable {
  private final LeasePool<DecompInterface> injectedPool;
  private final Supplier<Program> fallbackProgram;
  private final Object poolLock = new Object();
  private final Map<Program, LeasePool<DecompInterface>> programPools = new IdentityHashMap<>();
  private boolean closed;
  private final Map<DecompInterface, Boolean> commentModes =
      Collections.synchronizedMap(new WeakHashMap<>());
  private final Map<DecompInterface, CacheState> cacheStates =
      Collections.synchronizedMap(new WeakHashMap<>());

  DecompilerPool(
      int maxSize, Supplier<DecompInterface> factory, Consumer<DecompInterface> destroyer) {
    this(new LeasePool<>(maxSize, factory, destroyer), () -> null);
  }

  DecompilerPool(LeasePool<DecompInterface> pool, Supplier<Program> fallbackProgram) {
    this.injectedPool = Objects.requireNonNull(pool, "pool");
    this.fallbackProgram = Objects.requireNonNull(fallbackProgram, "fallbackProgram");
  }

  private DecompilerPool(Supplier<Program> fallbackProgram) {
    this.injectedPool = null;
    this.fallbackProgram = Objects.requireNonNull(fallbackProgram, "fallbackProgram");
  }

  /** Creates a bounded decompiler pool for {@code program}. */
  public static DecompilerPool create(Program program) {
    Objects.requireNonNull(program, "program");
    return new DecompilerPool(DecompilerPoolFactory.create(program), () -> program);
  }

  /** Creates a decompiler pool that keeps one bounded pool for each open program. */
  public static DecompilerPool forSession(GhidraSession context) {
    Objects.requireNonNull(context, "context");
    return new DecompilerPool(context::currentProgramOrNull);
  }

  /** Decompiles {@code function} with a bounded timeout and comment display mode. */
  public DecompileResults decompile(Function function, int timeoutMs, boolean includeComments) {
    Objects.requireNonNull(function, "function");
    LeasePool<DecompInterface> pool = poolFor(function.getProgram());
    try (LeasePool.Lease<DecompInterface> lease = pool.acquire()) {
      int timeoutSeconds = GhidraTimeout.secondsForMilliseconds(timeoutMs);
      DecompInterface decompiler = lease.value();
      applyCommentMode(decompiler, includeComments);
      // The native process keeps program data. Clear it when program modifications occur.
      flushCacheIfNeeded(decompiler, function.getProgram());
      return decompiler.decompileFunction(function, timeoutSeconds, null);
    }
  }

  /** Decompiles {@code function} with default options and returns its {@link HighFunction}. */
  public HighFunction decompileHighFunction(Function function) {
    if (function == null || function.isExternal()) {
      return null;
    }
    AddressSetView body = function.getBody();
    if (body == null || body.isEmpty()) {
      return null;
    }
    DecompileResults results =
        decompile(function, DecompilationService.DEFAULT_TIMEOUT_MS, false);
    return results != null && results.decompileCompleted() ? results.getHighFunction() : null;
  }

  /** Closes and removes the decompiler pool for a closed program. */
  public void releaseProgram(Program program) {
    if (program == null) {
      return;
    }
    LeasePool<DecompInterface> pool;
    synchronized (poolLock) {
      pool = programPools.remove(program);
    }
    if (pool != null) {
      pool.close();
    }
  }

  @Override
  public void close() {
    List<LeasePool<DecompInterface>> pools;
    synchronized (poolLock) {
      closed = true;
      pools = List.copyOf(programPools.values());
      programPools.clear();
    }
    if (injectedPool != null) {
      injectedPool.close();
    }
    for (LeasePool<DecompInterface> pool : pools) {
      pool.close();
    }
  }

  private LeasePool<DecompInterface> poolFor(Program program) {
    if (injectedPool != null) {
      synchronized (poolLock) {
        if (closed) {
          throw new IllegalStateException("decompilation service is closed");
        }
        return injectedPool;
      }
    }
    Program target = program != null ? program : fallbackProgram.get();
    if (target == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    synchronized (poolLock) {
      if (closed) {
        throw new IllegalStateException("decompilation service is closed");
      }
      return programPools.computeIfAbsent(target, DecompilerPoolFactory::create);
    }
  }

  /** Sends display options only when the comment mode of the pooled decompiler changes. */
  private void applyCommentMode(DecompInterface decompiler, boolean includeComments) {
    if (Boolean.valueOf(includeComments).equals(commentModes.get(decompiler))) {
      return;
    }
    commentModes.remove(decompiler);
    if (!decompiler.setOptions(DecompilerPoolFactory.options(includeComments))) {
      throw new IllegalStateException("unable to set decompiler display options");
    }
    commentModes.put(decompiler, includeComments);
  }

  /** Flushes the native cache only when the program or its modification number changes. */
  private void flushCacheIfNeeded(DecompInterface decompiler, Program program) {
    Program target = program != null ? program : fallbackProgram.get();
    if (target == null) {
      cacheStates.put(decompiler, CacheState.dirtyWithoutProgram());
      decompiler.flushCache();
      return;
    }
    long modificationNumber = target.getModificationNumber();
    CacheState state = cacheStates.get(decompiler);
    if (state == null) {
      Program openedProgram = decompiler.getProgram();
      if (openedProgram == null || openedProgram == target) {
        cacheStates.put(decompiler, CacheState.clean(target, modificationNumber));
        return;
      }
    } else if (state.isCleanFor(target, modificationNumber)) {
      return;
    }
    cacheStates.put(
        decompiler, state == null ? CacheState.dirtyWithoutProgram() : state.markDirty());
    if (decompiler.flushCache() >= 0) {
      cacheStates.put(decompiler, CacheState.clean(target, modificationNumber));
    }
  }

  private record CacheState(
      WeakReference<Program> program, long modificationNumber, boolean dirty) {
    private static final WeakReference<Program> NO_PROGRAM = new WeakReference<>(null);

    static CacheState clean(Program program, long modificationNumber) {
      return new CacheState(new WeakReference<>(program), modificationNumber, false);
    }

    static CacheState dirtyWithoutProgram() {
      return new CacheState(NO_PROGRAM, 0L, true);
    }

    CacheState markDirty() {
      return dirty ? this : new CacheState(program, modificationNumber, true);
    }

    boolean isCleanFor(Program candidate, long candidateModificationNumber) {
      return !dirty
          && program.refersTo(candidate)
          && modificationNumber == candidateModificationNumber;
    }
  }
}
