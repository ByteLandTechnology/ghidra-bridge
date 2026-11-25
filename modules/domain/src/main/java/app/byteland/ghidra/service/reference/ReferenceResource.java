package app.byteland.ghidra.service.reference;

/**
 * Cross-reference between two program locations.
 *
 * @param from source instruction or data address
 * @param to destination address
 * @param type reference type name
 * @param operandIndex source operand index, or {@code -1} for mnemonic references
 * @param primary whether this is the primary reference on the operand
 * @param sourceType symbol/reference source classification
 */
public record ReferenceResource(
    String from, String to, String type, int operandIndex, boolean primary, String sourceType) {}
