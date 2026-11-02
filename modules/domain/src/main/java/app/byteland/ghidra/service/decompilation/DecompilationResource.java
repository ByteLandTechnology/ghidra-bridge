package app.byteland.ghidra.service.decompilation;

import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
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
    List<Line> lines,
    List<CommentResource> comments,
    Boolean commentsComplete,
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
    if (format == Format.DOCUMENT && (c == null || lines == null)) {
      throw new IllegalArgumentException("document decompilation requires c and lines");
    }
    tokens = immutableCopyOrNull(tokens);
    lines = immutableCopyOrNull(lines);
    comments = immutableCopyOrNull(comments);
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

  /** One GUI line. Columns use zero-based UTF-16 offsets, with indentation. */
  public record Line(int number, int indent, List<LocatedToken> tokens) {
    public Line {
      tokens = List.copyOf(tokens);
    }
  }

  /** The token address and the GUI cursor address have separate meanings. */
  public record LocatedToken(
      Token.Kind kind,
      String text,
      int start,
      int end,
      String address,
      String maxAddress,
      String locationAddress,
      String codeUnitAddress,
      SymbolResource symbol) {}

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
    TOKENS,
    DOCUMENT
  }
}
