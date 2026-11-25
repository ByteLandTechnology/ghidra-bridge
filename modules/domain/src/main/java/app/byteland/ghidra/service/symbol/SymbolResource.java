package app.byteland.ghidra.service.symbol;

/**
 * Program symbol table entry metadata.
 *
 * @param id unique decimal symbol identifier
 * @param name symbol name
 * @param address symbol address
 * @param namespace enclosing namespace path
 * @param type symbol type name
 * @param sourceType symbol origin classification
 * @param primary whether the symbol is primary at its address
 * @param demangledName demangled C++/Rust symbol name, or {@code null}
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
