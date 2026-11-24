package app.byteland.ghidra.service.listing;

/**
 * Receipt returned after a request clears code units in an address range.
 */
public record ClearedCodeUnitsResource(String start, String end, long length) {}
