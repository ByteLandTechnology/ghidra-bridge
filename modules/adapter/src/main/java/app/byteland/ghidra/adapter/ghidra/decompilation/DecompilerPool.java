package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;

/**
 * Shares pooled decompiler instances and tracks program cache state across services.
 */
public final class DecompilerPool implements AutoCloseable {
  @FunctionalInterface
  interface DecompileCallback<R> {
    R accept(DecompileResults results, long startedAtNanos);
  }

  private final GhidraSession context;
  private final LeasePool<DecompInterface> leasePool;
  private final Map<DecompInterface, Boolean> commentModes =
      Collections.synchronizedMap(new WeakHashMap<>());
  private final Map<DecompInterface, Long> programModifications =
      Collections.synchronizedMap(new WeakHashMap<>());

  public static DecompilerPool create(GhidraSession context) {
    Objects.requireNonNull(context, "context");
    return new DecompilerPool(context, DecompilerPoolFactory.create(context::currentProgram));
  }

  DecompilerPool(GhidraSession context, LeasePool<DecompInterface> leasePool) {
    this.context = Objects.requireNonNull(context, "context");
    this.leasePool = Objects.requireNonNull(leasePool, "leasePool");
  }

  <R> R withDecompileResults(
      Function function,
      int timeoutMs,
      boolean includeComments,
      DecompileCallback<R> callback) {
    Objects.requireNonNull(function, "function");
    Objects.requireNonNull(callback, "callback");
    try (LeasePool.Lease<DecompInterface> lease = leasePool.acquire()) {
      long startedAt = System.nanoTime();
      int timeoutSeconds = GhidraTimeout.secondsForMilliseconds(timeoutMs);
      DecompInterface decompiler = lease.value();
      applyCommentMode(decompiler, includeComments);
      // The native process keeps program data. Clear it when program modifications occur.
      flushCacheIfModified(decompiler, function.getProgram());
      DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, null);
      return callback.accept(results, startedAt);
    }
  }

  /**
   * Decompiles one function and returns its high-level symbol model.
   *
   * @param function target function
   * @return high-level function or null when unavailable
   */
  public HighFunction decompileHighFunction(Function function) {
    return withDecompileResults(
        function,
        DecompilationService.DEFAULT_TIMEOUT_MS,
        false,
        (results, startedAt) -> results == null ? null : results.getHighFunction());
  }

  @Override
  public void close() {
    leasePool.close();
  }

  /** Sends display options only when the comment mode of the pooled decompiler changes. */
  private void applyCommentMode(DecompInterface decompiler, boolean includeComments) {
    if (Boolean.valueOf(includeComments).equals(commentModes.get(decompiler))) return;
    commentModes.remove(decompiler);
    if (!decompiler.setOptions(DecompilerPoolFactory.options(includeComments))) {
      throw new IllegalStateException("unable to set decompiler display options");
    }
    commentModes.put(decompiler, includeComments);
  }

  /** Flushes the native cache only when the modification number of the program changes. */
  private void flushCacheIfModified(DecompInterface decompiler, Program program) {
    Program target = program != null ? program : context.currentProgramOrNull();
    if (target == null) {
      programModifications.remove(decompiler);
      decompiler.flushCache();
      return;
    }
    long modificationNumber = target.getModificationNumber();
    if (Long.valueOf(modificationNumber).equals(programModifications.get(decompiler))) return;
    programModifications.remove(decompiler);
    if (decompiler.flushCache() >= 0) {
      programModifications.put(decompiler, modificationNumber);
    }
  }
}
