package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Defined data item in the program listing.
 *
 * @param address data unit start address
 * @param length byte length of the data item
 * @param dataType defined data type reference
 * @param value formatted scalar or string value, or {@code null}
 * @param representation listing display representation
 * @param bytes raw bytes of the data unit
 */
public record DataUnitResource(
    String address,
    int length,
    DataTypeReference dataType,
    String value,
    String representation,
    ByteSequence bytes) {}
