package app.byteland.ghidra.service.function;

/**
 * Selects a function by exact entry address, body address, or symbol name.
 */
public sealed interface FunctionSelector
    permits FunctionSelector.Entry, FunctionSelector.Containing, FunctionSelector.Symbol {
  /**
   * Selects a function by its exact entry point address.
   */
  record Entry(String entry) implements FunctionSelector {
    public Entry {
      if (entry == null || entry.isBlank()) {
        throw new IllegalArgumentException("entry is required");
      }
    }
  }

  /**
   * Selects a function whose body contains the given address.
   */
  record Containing(String address) implements FunctionSelector {
    public Containing {
      if (address == null || address.isBlank()) {
        throw new IllegalArgumentException("address is required");
      }
    }
  }

  /**
   * Selects a function by symbol name and optional parent namespace.
   */
  record Symbol(String name, String namespace) implements FunctionSelector {
    public Symbol {
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException("name is required");
      }
    }
  }
}
