package app.byteland.ghidra.adapter.ghidra.decompilation;

final class DecompilationFormatter {
  private DecompilationFormatter() {}

  static String formatCCode(String raw) {
    if (raw == null || raw.isEmpty()) {
      return raw;
    }
    CCodeFormatState state = new CCodeFormatState();
    StringBuilder output = new StringBuilder(raw.length());

    while (state.hasRemaining(raw)) {
      if (state.isInComment()) {
        state.handleCommentChar(raw, output);
        continue;
      }

      if (state.startsBlockComment(raw)) {
        state.startBlockComment(output);
        continue;
      }

      state.handleCodeChar(raw, output);
    }
    return output.toString().trim();
  }
}
