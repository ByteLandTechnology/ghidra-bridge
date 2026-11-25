package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Defined global data item and primary symbol metadata at an address.
 *
 * @param address canonical variable address
 * @param name primary symbol name when defined
 * @param namespace symbol namespace path when defined
 * @param dataType defined data type reference
 * @param length defined byte length
 * @param value formatted value string when available
 * @param representation display representation string
 * @param sourceType symbol source classification when defined
 */
public record GlobalVariableResource(
    String address,
    String name,
    String namespace,
    DataTypeReference dataType,
    int length,
    String value,
    String representation,
    String sourceType) {}
