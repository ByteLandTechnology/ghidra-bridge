package app.byteland.ghidra.service.search;

import java.util.List;
import java.util.Objects;

/**
 * Holds matched addresses for one wildcard byte pattern in a batch scan.
 */
public record BytePatternMatchesResource(
    int index, String pattern, List<String> matches, int matchCount) {
  public BytePatternMatchesResource {
    if (index < 0) throw new IllegalArgumentException("index must not be negative");
    Objects.requireNonNull(pattern, "pattern");
    matches = List.copyOf(Objects.requireNonNull(matches, "matches"));
    if (matchCount != matches.size()) {
      throw new IllegalArgumentException("matchCount must equal matches size");
    }
  }
}
