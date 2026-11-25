package app.byteland.ghidra.service.program;

import java.time.Instant;

/**
 * Summary metadata for the active Ghidra program.
 *
 * @param name program name in the project
 * @param executablePath imported executable path, or {@code null}
 * @param executableFormat loader format name, or {@code null}
 * @param imageBase image base address
 * @param minAddress minimum initialized or defined program address, or {@code null}
 * @param maxAddress maximum initialized or defined program address, or {@code null}
 * @param languageId Ghidra language identifier
 * @param compilerSpecId Ghidra compiler specification identifier
 * @param createdAt creation timestamp, or {@code null}
 * @param modifiedAt last modification timestamp, or {@code null}
 * @param functionCount total number of defined functions
 * @param symbolCount total number of symbols
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
