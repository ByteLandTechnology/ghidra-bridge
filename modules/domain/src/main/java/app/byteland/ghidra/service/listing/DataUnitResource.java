package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Represents a defined data item in the program listing.
 *
 * @param address canonical start address
 * @param length data item length in bytes
 * @param dataType defined data type reference
 * @param value formatted scalar or string value
 * @param representation human-readable value representation
 * @param bytes raw byte sequence
 */
public record DataUnitResource(
    String address,
    int length,
    DataTypeReference dataType,
    String value,
    String representation,
    ByteSequence bytes) {}
