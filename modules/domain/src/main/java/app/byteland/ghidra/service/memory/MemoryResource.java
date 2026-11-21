package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;

/**
 * Holds encoded bytes read from a program memory address range.
 *
 * @param address canonical start address
 * @param bytes encoded byte sequence
 */
public record MemoryResource(String address, ByteSequence bytes) {}
