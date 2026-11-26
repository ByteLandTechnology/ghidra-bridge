package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/** Reads and updates boolean analyzer options directly on a Ghidra program. */
final class AnalysisOptionsSupport {
  private AnalysisOptionsSupport() {}

  static Map<String, String> readBooleanOptions(Program program) {
    Objects.requireNonNull(program, "program");
    Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
    Map<String, String> values = new LinkedHashMap<>();
    for (String optionName : options.getOptionNames()) {
      if (options.getType(optionName) == OptionType.BOOLEAN_TYPE) {
        values.put(optionName, Boolean.toString(options.getBoolean(optionName, false)));
      }
    }
    return values;
  }

  static void writeBooleanOptions(
      GhidraSession context, Program program, Map<String, String> updates) {
    Objects.requireNonNull(context, "context");
    Objects.requireNonNull(program, "program");
    if (updates == null || updates.isEmpty()) {
      return;
    }
    context.withProgramTransaction(
        program,
        () -> {
          Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
          for (Map.Entry<String, String> entry : updates.entrySet()) {
            String name = entry.getKey();
            if (!options.contains(name) || options.getType(name) != OptionType.BOOLEAN_TYPE) {
              throw new IllegalArgumentException("analyzer option is unavailable: " + name);
            }
            options.setBoolean(name, Boolean.parseBoolean(entry.getValue()));
          }
          return null;
        });
  }
}
