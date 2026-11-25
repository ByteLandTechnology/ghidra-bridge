package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Defined global data item and primary symbol metadata at an address.
 *
 * @param address variable start address
 * @param name primary symbol name, or {@code null} when unnamed
 * @param namespace symbol namespace path
 * @param dataType defined data type reference
 * @param length size in bytes
 * @param value formatted data value, if available
 * @param representation human-readable data representation
 * @param sourceType symbol source type name
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
