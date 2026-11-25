package app.byteland.ghidra.service.address;

/**
 * Represents address metadata and associated program components.
 *
 * @param address formatted address string
 * @param valid always true because the address parser succeeded
 * @param inMemory true if the address is inside any program memory block
 * @param memoryBlock summary of the memory block that contains the address
 * @param function summary of the function that contains the address
 * @param symbol summary of the primary symbol at this address
 * @param codeUnit summary of the code unit that contains the address, or {@code null}
 */
public record AddressResource(
    String address,
    boolean valid,
    boolean inMemory,
    MemoryBlockSummary memoryBlock,
    FunctionSummary function,
    SymbolSummary symbol,
    CodeUnitSummary codeUnit) {
  /**
   * Summarizes the start and end bounds of a code unit containing an address.
   *
   * @param address canonical start address of the code unit
   * @param end canonical inclusive end address of the code unit
   */
  public record CodeUnitSummary(String address, String end) {}

  /**
   * Summarizes memory block attributes for an address.
   *
   * @param name memory block name
   * @param start canonical block start address
   * @param end canonical inclusive block end address
   * @param length block size in bytes
   * @param read {@code true} if the block is readable
   * @param write {@code true} if the block is writable
   * @param execute {@code true} if the block is executable
   */
  public record MemoryBlockSummary(
      String name,
      String start,
      String end,
      long length,
      boolean read,
      boolean write,
      boolean execute) {}

  /**
   * Summarizes the function that contains an address.
   *
   * @param entry canonical function entry-point address
   * @param name function name
   */
  public record FunctionSummary(String entry, String name) {}

  /**
   * Summarizes the primary symbol for an address.
   *
   * @param id numeric symbol identifier formatted as a string
   * @param name symbol name
   * @param type Ghidra symbol type label
   */
  public record SymbolSummary(String id, String name, String type) {}
}
