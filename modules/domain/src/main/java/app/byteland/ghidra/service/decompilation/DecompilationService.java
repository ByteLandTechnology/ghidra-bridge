package app.byteland.ghidra.service.decompilation;

import app.byteland.ghidra.service.function.FunctionSelector;

/**
 * Decompiles machine code to high-level representations.
 */
public interface DecompilationService extends AutoCloseable {
  int DEFAULT_TIMEOUT_MS = 30_000;
  int MIN_TIMEOUT_MS = 100;
  int MAX_TIMEOUT_MS = 300_000;

  /**
   * Decompiles the function whose entry point is the given address.
   *
   * @param rawAddress function entry point address
   * @param format output representation format
   * @param timeoutMs maximum time in milliseconds
   * @return decompilation output resource
   */
  DecompilationResource decompileFunction(
      String rawAddress, DecompilationResource.Format format, Integer timeoutMs,
      boolean includeComments);

  /**
   * Decompiles the function identified by an entry, containing address, or symbol selector.
   *
   * @param selector function target selector
   * @param format output representation format
   * @param timeoutMs maximum time in milliseconds
   * @param includeComments whether to include comments in output
   * @return decompilation output resource
   */
  default DecompilationResource decompileFunction(
      FunctionSelector selector,
      DecompilationResource.Format format,
      Integer timeoutMs,
      boolean includeComments) {
    if (selector instanceof FunctionSelector.Entry entry) {
      return decompileFunction(entry.entry(), format, timeoutMs, includeComments);
    }
    throw new UnsupportedOperationException("selector decompilation is not implemented");
  }

  /**
   * Closes active decompiler resources.
   */
  @Override
  void close();
}
