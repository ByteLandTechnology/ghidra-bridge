package app.byteland.ghidra.adapter.ghidra.program;

import ghidra.program.model.listing.Program;
import java.io.File;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class ProgramTimestamps {
  private ProgramTimestamps() {}

  static Instant createdTimestamp(Program program) {
    if (program.getDomainFile() == null) {
      return null;
    }
    Map<String, String> metadata = program.getDomainFile().getMetadata();
    if (metadata != null) {
      for (String key : List.of("Date Created", "Created", "Creation Date", "DATE_CREATED")) {
        String value = metadata.get(key);
        if (value != null && !value.isBlank()) {
          Instant normalized = normalize(value);
          if (normalized != null) return normalized;
        }
      }
    }
    return modifiedTimestamp(program);
  }

  static Instant modifiedTimestamp(Program program) {
    if (program.getDomainFile() == null) {
      return executableTimestamp(program);
    }
    long epochMillis = program.getDomainFile().getLastModifiedTime();
    if (epochMillis > 0) {
      return Instant.ofEpochMilli(epochMillis);
    }
    return executableTimestamp(program);
  }

  static Instant executableTimestamp(Program program) {
    String executablePath = program.getExecutablePath();
    if (executablePath == null || executablePath.isBlank()) {
      return null;
    }
    File executable = new File(executablePath);
    long epochMillis = executable.isFile() ? executable.lastModified() : 0L;
    return epochMillis > 0 ? Instant.ofEpochMilli(epochMillis) : null;
  }

  private static Instant normalize(String value) {
    String text = value.trim();
    try {
      return Instant.parse(text);
    } catch (DateTimeParseException ignored) {
    }
    try {
      return OffsetDateTime.parse(text).toInstant();
    } catch (DateTimeParseException ignored) {
    }
    for (DateTimeFormatter formatter :
        List.of(
            DateTimeFormatter.RFC_1123_DATE_TIME,
            DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH))) {
      try {
        return ZonedDateTime.parse(text, formatter).toInstant();
      } catch (DateTimeParseException ignored) {
      }
    }
    try {
      long epoch = Long.parseLong(text);
      return Instant.ofEpochMilli(epoch);
    } catch (NumberFormatException ignored) {
      return null;
    }
  }
}
