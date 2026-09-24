package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.service.decompilation.DecompilationResource.Token;
import java.util.List;

final class DecompilationPayload {
  final boolean completed;
  final long elapsedMs;
  final String code;
  final List<Token> tokens;
  final List<String> warnings;

  DecompilationPayload(
      boolean completed, long elapsedMs, String code, List<Token> tokens, List<String> warnings) {
    this.completed = completed;
    this.elapsedMs = elapsedMs;
    this.code = code;
    this.tokens = tokens;
    this.warnings = warnings;
  }
}
