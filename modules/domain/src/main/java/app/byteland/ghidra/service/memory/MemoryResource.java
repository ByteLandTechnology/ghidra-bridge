package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;

public record MemoryResource(String address, ByteSequence bytes) {}
