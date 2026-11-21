package app.byteland.ghidra.service.program;

import app.byteland.ghidra.service.address.AddressResource.FunctionSummary;

/**
 * Describes one exported symbol or external entry point in the active program.
 *
 * @param address canonical program address
 * @param name symbol name at the entry point
 * @param demangledName demangled symbol name when present
 * @param namespace parent namespace name
 * @param isFunction true when a function exists at this entry point
 * @param function function summary when a function exists at this entry point
 * @param ordinal export ordinal when present
 */
public record ExportResource(
    String address,
    String name,
    String demangledName,
    String namespace,
    boolean isFunction,
    FunctionSummary function,
    Integer ordinal) {}
