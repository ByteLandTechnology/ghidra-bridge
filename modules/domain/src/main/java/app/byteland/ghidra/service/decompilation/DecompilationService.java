package app.byteland.ghidra.service.decompilation;

/**
 * Decompiles machine code to high-level representations.
 */
public interface DecompilationService extends AutoCloseable {
  /** Default decompilation timeout in milliseconds. */
  int DEFAULT_TIMEOUT_MS = 30_000;

  /** Minimum allowed decompilation timeout in milliseconds. */
  int MIN_TIMEOUT_MS = 100;

  /** Maximum allowed decompilation timeout in milliseconds. */
  int MAX_TIMEOUT_MS = 300_000;

  /**
   * Decompiles the function whose entry point is the given address.
   *
   * @param rawAddress function entry point address
   * @param format output representation format
   * @param timeoutMs maximum time in milliseconds
   * @param includeComments whether to include comments in the function body
   * @return decompilation output resource
   */
  DecompilationResource decompileFunction(
      String rawAddress, DecompilationResource.Format format, Integer timeoutMs,
      boolean includeComments);

  /**
   * Closes active decompiler resources.
   */
  @Override
  void close();
}
