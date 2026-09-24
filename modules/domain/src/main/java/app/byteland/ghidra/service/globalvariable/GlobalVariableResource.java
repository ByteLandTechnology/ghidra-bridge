package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.datatype.DataTypeReference;

public record GlobalVariableResource(
    String address,
    String name,
    String namespace,
    DataTypeReference dataType,
    int length,
    String value,
    String representation,
    String sourceType) {}
