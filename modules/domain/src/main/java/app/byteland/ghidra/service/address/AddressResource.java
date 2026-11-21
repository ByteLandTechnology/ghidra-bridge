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
 * @param codeUnit summary of the code unit that contains the address
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
   * Summarizes the code unit span that contains an address.
   *
   * @param address first address of the code unit
   * @param end last address of the code unit
   */
  public record CodeUnitSummary(String address, String end) {}

  /**
   * Summarizes memory block attributes for an address.
   *
   * @param name memory block name
   * @param start first address in the block
   * @param end last address in the block
   * @param length block size in bytes
   * @param read true when the block permits reads
   * @param write true when the block permits writes
   * @param execute true when the block permits execution
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
   * @param entry function entry point address
   * @param name function symbol name
   */
  public record FunctionSummary(String entry, String name) {}

  /**
   * Summarizes the primary symbol for an address.
   *
   * @param id unique symbol identifier string
   * @param name symbol name
   * @param type symbol classification name
   */
  public record SymbolSummary(String id, String name, String type) {}
}
