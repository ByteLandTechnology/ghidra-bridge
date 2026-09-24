package app.byteland.ghidra.service.reference;

public record ReferenceResource(
    String from, String to, String type, int operandIndex, boolean primary, String sourceType) {}
