package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Describes one decoded string in program memory.
 */
public record StringResource(
    String address,
    int length,
    String value,
    String encoding,
    boolean defined,
    DataTypeReference dataType) {}
