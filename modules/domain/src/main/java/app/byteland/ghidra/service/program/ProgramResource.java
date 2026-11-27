package app.byteland.ghidra.service.program;

import java.time.Instant;

/**
 * Summary metadata and counts for the active Ghidra program.
 *
 * @param name program name
 * @param executablePath imported executable path, or {@code null}
 * @param executableFormat executable file format name, or {@code null}
 * @param imageBase canonical image base address
 * @param minAddress canonical minimum defined address, or {@code null}
 * @param maxAddress canonical maximum defined address, or {@code null}
 * @param languageId Ghidra language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param createdAt program creation timestamp, or {@code null}
 * @param modifiedAt last modification timestamp, or {@code null}
 * @param functionCount total number of defined functions
 * @param symbolCount total number of symbols in the symbol table
 */
public record ProgramResource(
    String name,
    String executablePath,
    String executableFormat,
    String imageBase,
    String minAddress,
    String maxAddress,
    String languageId,
    String compilerSpecId,
    Instant createdAt,
    Instant modifiedAt,
    long functionCount,
    long symbolCount) {}
