package app.byteland.ghidra.service.reference;

/**
 * Represents a directed code or data reference between two addresses.
 *
 * @param from source address
 * @param to destination address
 * @param type reference classification name
 * @param operandIndex source operand index, or {@code -1} for mnemonic references
 * @param primary true when marked as the primary reference on the operand
 * @param sourceType reference source classification
 */
public record ReferenceResource(
    String from, String to, String type, int operandIndex, boolean primary, String sourceType) {}
