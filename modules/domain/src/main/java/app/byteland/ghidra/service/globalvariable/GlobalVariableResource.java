package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Represents a defined global data item and its primary symbol metadata.
 *
 * @param address canonical memory address
 * @param name primary symbol name
 * @param namespace symbol namespace path
 * @param dataType defined data type reference
 * @param length data item length in bytes
 * @param value formatted scalar or string value
 * @param representation human-readable listing value representation
 * @param sourceType symbol source classification
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
