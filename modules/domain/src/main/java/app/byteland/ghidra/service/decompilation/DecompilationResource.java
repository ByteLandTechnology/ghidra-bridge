package app.byteland.ghidra.service.decompilation;

import java.util.List;
import java.util.Objects;

public record DecompilationResource(
    String entry,
    String name,
    Format format,
    boolean completed,
    long elapsedMs,
    String c,
    List<Token> tokens,
    List<String> warnings) {
  public DecompilationResource {
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(format, "format");
    if (format == Format.TEXT && c == null) {
      throw new IllegalArgumentException("text decompilation requires c");
    }
    if (format == Format.TEXT && tokens != null) {
      throw new IllegalArgumentException("text decompilation must not contain tokens");
    }
    if (format == Format.TOKENS && tokens == null) {
      throw new IllegalArgumentException("token decompilation requires tokens");
    }
    if (format == Format.TOKENS && c != null) {
      throw new IllegalArgumentException("token decompilation must not contain c");
    }
    tokens = immutableCopyOrNull(tokens);
    Objects.requireNonNull(warnings, "warnings");
    warnings = List.copyOf(warnings);
  }

  @Override
  public List<Token> tokens() {
    return immutableCopyOrNull(tokens);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  public record Token(Kind kind, String text, String address) {
    public Token {
      if (kind == null) throw new IllegalArgumentException("token kind is required");
      if (text == null) throw new IllegalArgumentException("token text is required");
    }

    public enum Kind {
      KEYWORD,
      COMMENT,
      TYPE,
      FUNCTION,
      VARIABLE,
      CONSTANT,
      PARAMETER,
      GLOBAL,
      DEFAULT,
      ERROR,
      SPECIAL
    }
  }

  public enum Format {
    TEXT,
    TOKENS
  }
}
