package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;

/**
 * Contiguous byte slice read from program memory.
 *
 * @param address start address of the byte range
 * @param bytes encoded byte sequence
 */
public record MemoryResource(String address, ByteSequence bytes) {}
