package app.byteland.ghidra.service.symbol;

/**
 * Program symbol table entry metadata.
 *
 * @param id unique decimal symbol identifier
 * @param name symbol name
 * @param address canonical symbol address
 * @param namespace symbol namespace path
 * @param type Ghidra symbol type name
 * @param sourceType symbol source classification
 * @param primary whether the symbol is primary at its address
 * @param demangledName optional demangled C++ display name
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
