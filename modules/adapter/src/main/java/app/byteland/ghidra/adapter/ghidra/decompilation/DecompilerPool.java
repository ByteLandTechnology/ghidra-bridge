package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.service.decompilation.DecompilationService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Shares a bounded pool of {@link DecompInterface} instances across session services. */
public final class DecompilerPool implements AutoCloseable {
  private final LeasePool<DecompInterface> pool;
  private final Supplier<Program> fallbackProgram;
  private final Map<DecompInterface, Boolean> commentModes =
      Collections.synchronizedMap(new WeakHashMap<>());
  private final Map<DecompInterface, Long> programModifications =
      Collections.synchronizedMap(new WeakHashMap<>());

  DecompilerPool(
      int maxSize, Supplier<DecompInterface> factory, Consumer<DecompInterface> destroyer) {
    this(new LeasePool<>(maxSize, factory, destroyer), () -> null);
  }

  DecompilerPool(LeasePool<DecompInterface> pool, Supplier<Program> fallbackProgram) {
    this.pool = Objects.requireNonNull(pool, "pool");
    this.fallbackProgram = Objects.requireNonNull(fallbackProgram, "fallbackProgram");
  }

  /** Creates a bounded decompiler pool for {@code program}. */
  public static DecompilerPool create(Program program) {
    Objects.requireNonNull(program, "program");
    return new DecompilerPool(DecompilerPoolFactory.create(program), () -> program);
  }

  /** Decompiles {@code function} with a bounded timeout and comment display mode. */
  public DecompileResults decompile(Function function, int timeoutMs, boolean includeComments) {
    Objects.requireNonNull(function, "function");
    try (LeasePool.Lease<DecompInterface> lease = pool.acquire()) {
      int timeoutSeconds = GhidraTimeout.secondsForMilliseconds(timeoutMs);
      DecompInterface decompiler = lease.value();
      applyCommentMode(decompiler, includeComments);
      // The native process keeps program data. Clear it when program modifications occur.
      flushCacheIfModified(decompiler, function.getProgram());
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

  int maxSize() {
    return pool.maxSize();
  }

  int createdCount() {
    return pool.createdCount();
  }

  @Override
  public void close() {
    pool.close();
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

  /** Flushes the native cache only when the modification number of the program changes. */
  private void flushCacheIfModified(DecompInterface decompiler, Program program) {
    Program target = program != null ? program : fallbackProgram.get();
    if (target == null) {
      programModifications.remove(decompiler);
      decompiler.flushCache();
      return;
    }
    long modificationNumber = target.getModificationNumber();
    if (Long.valueOf(modificationNumber).equals(programModifications.get(decompiler))) {
      return;
    }
    programModifications.remove(decompiler);
    if (decompiler.flushCache() >= 0) {
      programModifications.put(decompiler, modificationNumber);
    }
  }
}
