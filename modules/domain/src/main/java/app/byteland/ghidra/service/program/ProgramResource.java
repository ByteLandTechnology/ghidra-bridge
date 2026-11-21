package app.byteland.ghidra.service.program;

import java.time.Instant;

/**
 * Summarizes metadata, address bounds, timestamps, and counts for the active Ghidra program.
 *
 * @param name program name
 * @param executablePath imported executable path
 * @param executableFormat executable file format name
 * @param imageBase image base address
 * @param minAddress minimum defined program address
 * @param maxAddress maximum defined program address
 * @param languageId Ghidra language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param createdAt optional program creation timestamp
 * @param modifiedAt optional last-modified timestamp
 * @param functionCount total function count
 * @param symbolCount total symbol count
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
