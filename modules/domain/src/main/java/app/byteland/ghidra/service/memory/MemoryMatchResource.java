package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;

/**
 * Describes one byte pattern match in initialized memory.
 */
public record MemoryMatchResource(String address, int length, ByteSequence bytes) {}
