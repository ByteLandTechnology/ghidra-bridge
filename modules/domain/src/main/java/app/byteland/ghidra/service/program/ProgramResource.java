package app.byteland.ghidra.service.program;

import java.time.Instant;

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
