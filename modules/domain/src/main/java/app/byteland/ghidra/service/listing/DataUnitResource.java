package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Defined listing data item metadata and bytes at an address.
 *
 * @param address canonical data unit start address
 * @param length defined byte length
 * @param dataType defined data type reference
 * @param value formatted value string when available
 * @param representation display representation string
 * @param bytes raw byte sequence when available
 */
public record DataUnitResource(
    String address,
    int length,
    DataTypeReference dataType,
    String value,
    String representation,
    ByteSequence bytes) {}
