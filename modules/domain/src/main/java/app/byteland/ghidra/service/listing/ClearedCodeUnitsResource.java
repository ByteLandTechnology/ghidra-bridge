package app.byteland.ghidra.service.listing;

/**
 * Receipt returned after clearing code units in an inclusive address range.
 */
public record ClearedCodeUnitsResource(String start, String end, long length) {}
