package app.byteland.ghidra.service.reference;

/**
 * Describes a code or data cross-reference between two program addresses.
 *
 * @param from canonical source address
 * @param to canonical destination address
 * @param type Ghidra reference type name
 * @param operandIndex zero-based source operand index, or {@code -1} when not operand-bound
 * @param primary {@code true} if marked as the primary reference on the operand
 * @param sourceType Ghidra reference source classification
 */
public record ReferenceResource(
    String from, String to, String type, int operandIndex, boolean primary, String sourceType) {}
