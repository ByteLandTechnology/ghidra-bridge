package app.byteland.ghidra.service.decompilation;

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
   * @param timeoutMs maximum execution budget in milliseconds
   * @return decompilation output resource
   */
  DecompilationResource decompileFunction(
      String rawAddress, DecompilationResource.Format format, Integer timeoutMs);

  /**
   * Closes active decompiler resources.
   */
  @Override
  void close();
}
