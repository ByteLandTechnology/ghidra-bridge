package app.byteland.ghidra.service.symbol;

/**
 * Describes a symbol in the active Ghidra program symbol table.
 *
 * @param id unique numeric symbol identifier formatted as text
 * @param name symbol name
 * @param address canonical symbol address
 * @param namespace parent namespace name, or {@code null}
 * @param type Ghidra symbol type name
 * @param sourceType Ghidra symbol source classification
 * @param primary {@code true} if this symbol is the primary symbol at its address
 * @param demangledName optional demangled C++ signature, or {@code null}
 */
public record SymbolResource(
    String id,
    String name,
    String address,
    String namespace,
    String type,
    String sourceType,
    boolean primary,
    String demangledName) {}
