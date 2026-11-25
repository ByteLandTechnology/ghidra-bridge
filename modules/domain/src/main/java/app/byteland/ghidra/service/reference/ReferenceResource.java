package app.byteland.ghidra.service.reference;

/**
 * Cross-reference edge between two program addresses.
 *
 * @param from source instruction or data address
 * @param to destination target address
 * @param type Ghidra reference type name
 * @param operandIndex operand index or {@code -1} for mnemonic references
 * @param primary whether the reference is marked primary on its operand
 * @param sourceType reference source classification
 */
public record ReferenceResource(
    String from, String to, String type, int operandIndex, boolean primary, String sourceType) {}
