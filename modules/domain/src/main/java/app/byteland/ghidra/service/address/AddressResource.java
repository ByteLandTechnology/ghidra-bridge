package app.byteland.ghidra.service.address;

/**
 * Represents address metadata and associated program components.
 *
 * @param address formatted address string
 * @param valid always true; the address expression parsed successfully
 * @param inMemory true if the address is inside any program memory block
 * @param memoryBlock summary of the containing memory block
 * @param function summary of the enclosing function
 * @param symbol summary of the primary symbol at this address
 */
public record AddressResource(
    String address,
    boolean valid,
    boolean inMemory,
    MemoryBlockSummary memoryBlock,
    FunctionSummary function,
    SymbolSummary symbol) {
  /**
   * Summarizes memory block attributes for an address.
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
   * Summarizes the enclosing function for an address.
   */
  public record FunctionSummary(String entry, String name) {}

  /**
   * Summarizes the primary symbol for an address.
   */
  public record SymbolSummary(String id, String name, String type) {}
}
