package app.byteland.ghidra.adapter.ghidra.function;

import java.util.Set;

final class FunctionIncludes {
  private FunctionIncludes() {}

  static Set<String> normalize(Set<String> includes) {
    return includes == null ? Set.of() : includes;
  }
}
