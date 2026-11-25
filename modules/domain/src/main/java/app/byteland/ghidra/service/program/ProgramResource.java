package app.byteland.ghidra.service.program;

import java.time.Instant;

/**
 * Summary metadata and counts for the active Ghidra program.
 *
 * @param name program name
 * @param executablePath imported executable path when recorded
 * @param executableFormat executable file format name
 * @param imageBase canonical image base address
 * @param minAddress minimum defined program address when present
 * @param maxAddress maximum defined program address when present
 * @param languageId Ghidra processor language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param createdAt program creation timestamp when recorded
 * @param modifiedAt last modification timestamp when recorded
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
