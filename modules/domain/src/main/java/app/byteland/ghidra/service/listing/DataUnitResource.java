package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Describes a defined data unit in the program.
 *
 * @param address canonical start address
 * @param length data unit byte length
 * @param dataType assigned data type reference
 * @param value formatted scalar value, or {@code null}
 * @param representation Ghidra display representation text
 * @param bytes raw data unit bytes
 */
public record DataUnitResource(
    String address,
    int length,
    DataTypeReference dataType,
    String value,
    String representation,
    ByteSequence bytes) {}
