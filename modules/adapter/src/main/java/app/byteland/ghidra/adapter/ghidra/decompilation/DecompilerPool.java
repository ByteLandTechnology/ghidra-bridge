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
  private final Map<DecompInterface, Boolean> commentModes =
      Collections.synchronizedMap(new WeakHashMap<>());

  DecompilerPool(
      int maxSize, Supplier<DecompInterface> factory, Consumer<DecompInterface> destroyer) {
    this.pool = new LeasePool<>(maxSize, factory, destroyer);
  }

  private DecompilerPool(LeasePool<DecompInterface> pool) {
    this.pool = Objects.requireNonNull(pool, "pool");
  }

  /** Creates a bounded decompiler pool for {@code program}. */
  public static DecompilerPool create(Program program) {
    Objects.requireNonNull(program, "program");
    return new DecompilerPool(DecompilerPoolFactory.create(program));
  }

  /** Decompiles {@code function} with a bounded timeout and comment display mode. */
  public DecompileResults decompile(Function function, int timeoutMs, boolean includeComments) {
    Objects.requireNonNull(function, "function");
    try (LeasePool.Lease<DecompInterface> lease = pool.acquire()) {
      int timeoutSeconds = GhidraTimeout.secondsForMilliseconds(timeoutMs);
      DecompInterface decompiler = lease.value();
      applyCommentMode(decompiler, includeComments);
      // The native process keeps program data. Clear it to show the current names and comments.
      decompiler.flushCache();
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
}
