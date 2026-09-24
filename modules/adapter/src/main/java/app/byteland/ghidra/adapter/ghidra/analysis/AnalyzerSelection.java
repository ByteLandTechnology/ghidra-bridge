package app.byteland.ghidra.adapter.ghidra.analysis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class AnalyzerSelection {
  private final List<String> analyzerNames;

  private AnalyzerSelection(List<String> analyzerNames) {
    this.analyzerNames = List.copyOf(analyzerNames);
  }

  static AnalyzerSelection from(List<String> analyzers) {
    if (analyzers == null) {
      return new AnalyzerSelection(List.of());
    }
    if (analyzers.isEmpty()) {
      throw new IllegalArgumentException("analyzers must not be empty");
    }

    Set<String> seen = new LinkedHashSet<>();
    for (String item : analyzers) {
      if (item == null || item.isBlank()) {
        throw new IllegalArgumentException("analyzers must be an array of analyzer names");
      }
      seen.add(item.trim());
    }
    return new AnalyzerSelection(new ArrayList<>(seen));
  }

  boolean hasSelection() {
    return !analyzerNames.isEmpty();
  }

  List<String> analyzers() {
    return analyzerNames;
  }
}
