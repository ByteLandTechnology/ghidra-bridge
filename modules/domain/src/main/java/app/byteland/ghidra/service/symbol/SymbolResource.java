package app.byteland.ghidra.service.symbol;

public record SymbolResource(
    String id,
    String name,
    String address,
    String namespace,
    String type,
    String sourceType,
    boolean primary) {}
