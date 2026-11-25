package app.byteland.ghidra.adapter.ghidra.decompilation;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;
import java.util.Objects;
import java.util.function.Supplier;

final class DecompilerPoolFactory {
  private DecompilerPoolFactory() {}

  static LeasePool<DecompInterface> create(Program program) {
    return create(() -> program);
  }

  static LeasePool<DecompInterface> create(Supplier<Program> programSupplier) {
    Objects.requireNonNull(programSupplier, "programSupplier");
    return new LeasePool<>(
        1, () -> createDecompiler(programSupplier.get()), DecompilerPoolFactory::destroyDecompiler);
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
