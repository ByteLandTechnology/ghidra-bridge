package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;

/**
 * Holds a contiguous byte range read from program memory.
 *
 * @param address canonical start address of the byte range
 * @param bytes encoded byte sequence
 */
public record MemoryResource(String address, ByteSequence bytes) {}
