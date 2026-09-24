package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;

public record DataUnitResource(
    String address,
    int length,
    DataTypeReference dataType,
    String value,
    String representation,
    ByteSequence bytes) {}
