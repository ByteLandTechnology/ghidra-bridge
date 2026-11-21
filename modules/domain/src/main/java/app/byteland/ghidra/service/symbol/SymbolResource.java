package app.byteland.ghidra.service.symbol;

/**
 * Represents a symbol table entry and optional demangled C++ name.
 *
 * @param id unique symbol identifier string
 * @param name symbol name
 * @param address canonical symbol address
 * @param namespace parent namespace path
 * @param type symbol classification name
 * @param sourceType symbol source classification
 * @param primary true when this symbol is primary at its address
 * @param demangledName optional demangled C++ name
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
