package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Describes a defined global data item and its primary label at a memory address.
 *
 * @param address canonical memory address
 * @param name primary symbol name, or {@code null}
 * @param namespace parent namespace name, or {@code null}
 * @param dataType structured data type reference
 * @param length defined data byte length
 * @param value formatted scalar value, or {@code null}
 * @param representation Ghidra display representation text
 * @param sourceType Ghidra symbol source classification, or {@code null}
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
