package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;

/**
 * Encoded byte range read from program memory.
 *
 * @param address canonical start address of the range
 * @param bytes encoded byte sequence
 */
public record MemoryResource(String address, ByteSequence bytes) {}
