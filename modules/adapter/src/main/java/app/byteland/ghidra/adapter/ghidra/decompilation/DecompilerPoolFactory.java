package app.byteland.ghidra.adapter.ghidra.decompilation;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;

final class DecompilerPoolFactory {
  static final int MIN_POOL_SIZE = 2;
  static final int MAX_POOL_SIZE = 4;

  private DecompilerPoolFactory() {}

  static LeasePool<DecompInterface> create(Program program) {
    return new LeasePool<>(
        poolSize(Runtime.getRuntime().availableProcessors()),
        () -> createDecompiler(program),
        DecompilerPoolFactory::destroyDecompiler);
  }

  static int poolSize(int availableProcessors) {
    return Math.clamp(availableProcessors, MIN_POOL_SIZE, MAX_POOL_SIZE);
  }

  private static DecompInterface createDecompiler(Program program) {
    DecompInterface decomp = new DecompInterface();
    decomp.setOptions(options(false));
    if (!decomp.openProgram(program)) {
      throw new IllegalStateException("unable to open program for decompilation");
    }
    return decomp;
  }

  static DecompileOptions options(boolean includeComments) {
    DecompileOptions options = new DecompileOptions();
    if (includeComments) {
      options.setPLATECommentIncluded(true);
      options.setPRECommentIncluded(true);
      options.setEOLCommentIncluded(true);
      options.setPOSTCommentIncluded(true);
    }
    return options;
  }

  private static void destroyDecompiler(DecompInterface decomp) {
    if (decomp == null) {
      return;
    }
    RuntimeException failure = null;
    try {
      decomp.closeProgram();
    } catch (RuntimeException closeFailure) {
      failure = closeFailure;
    }
    try {
      decomp.dispose();
    } catch (RuntimeException disposeFailure) {
      if (failure == null) {
        failure = disposeFailure;
      } else {
        addDistinctSuppressed(failure, disposeFailure);
      }
    }
    if (failure != null) {
      throw failure;
    }
  }

  private static void addDistinctSuppressed(
      RuntimeException failure, RuntimeException suppressedFailure) {
    if (failure != suppressedFailure) {
      failure.addSuppressed(suppressedFailure);
    }
  }
}
