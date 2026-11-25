package app.byteland.ghidra.service.decompilation;

import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import java.util.List;
import java.util.Objects;

/**
 * Decompiler output for a function in text, token, or structured document format.
 *
 * @param entry function entry point address
 * @param name function name
 * @param format output representation format
 * @param completed whether decompilation completed normally
 * @param elapsedMs elapsed decompilation wall time in milliseconds
 * @param c rendered C source text when included by {@code format}
 * @param tokens flat token list when {@code format} is {@link Format#TOKENS}
 * @param lines structured GUI lines when {@code format} is {@link Format#DOCUMENT}
 * @param comments collected program comments within the function, or {@code null}
 * @param commentsComplete whether all function comments were returned without truncation
 * @param warnings decompiler warning messages
 */
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
  /** Validates format-specific payload invariants and freezes collection fields. */
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

  /**
   * Returns flat syntax tokens when {@code format} is {@link Format#TOKENS}, or {@code null}.
   *
   * @return syntax token list, or {@code null}
   */
  @Override
  public List<Token> tokens() {
    return immutableCopyOrNull(tokens);
  }

  /**
   * Returns structured GUI lines when {@code format} is {@link Format#DOCUMENT}, or {@code null}.
   *
   * @return structured line list, or {@code null}
   */
  @Override
  public List<Line> lines() {
    return immutableCopyOrNull(lines);
  }

  /**
   * Returns collected program comments within the function, or {@code null}.
   *
   * @return function comment list, or {@code null}
   */
  @Override
  public List<CommentResource> comments() {
    return immutableCopyOrNull(comments);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * One GUI line. Columns use zero-based UTF-16 offsets, with indentation.
   *
   * @param number one-based line number
   * @param indent indentation level
   * @param tokens positioned tokens on this line
   */
  public record Line(int number, int indent, List<LocatedToken> tokens) {
    /** Freezes {@code tokens}. */
    public Line {
      tokens = List.copyOf(tokens);
    }
  }

  /**
   * Positioned token on a structured decompiler line. The token address and the GUI cursor address
   * have separate meanings.
   *
   * @param kind syntactic token classification
   * @param text rendered token text
   * @param start inclusive zero-based UTF-16 start column
   * @param end exclusive zero-based UTF-16 end column
   * @param address minimum instruction address associated with the token, or {@code null}
   * @param maxAddress maximum instruction address associated with the token, or {@code null}
   * @param locationAddress GUI navigation location address, or {@code null}
   * @param codeUnitAddress backing code unit address for comments, or {@code null}
   * @param symbol resolved program symbol associated with the token, or {@code null}
   */
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

  /**
   * Decompiler syntax token with an optional instruction address.
   *
   * @param kind syntactic token classification
   * @param text rendered token text
   * @param address associated instruction address, or {@code null}
   */
  public record Token(Kind kind, String text, String address) {
    /** Validates that {@code kind} and {@code text} are non-null. */
    public Token {
      if (kind == null) throw new IllegalArgumentException("token kind is required");
      if (text == null) throw new IllegalArgumentException("token text is required");
    }

    /** Syntactic token classification emitted by the decompiler. */
    public enum Kind {
      /** Language keyword token. */
      KEYWORD,
      /** Comment token. */
      COMMENT,
      /** Data type name token. */
      TYPE,
      /** Function identifier token. */
      FUNCTION,
      /** Local or temporary variable token. */
      VARIABLE,
      /** Numeric or literal constant token. */
      CONSTANT,
      /** Function parameter token. */
      PARAMETER,
      /** Global symbol token. */
      GLOBAL,
      /** Unspecialized syntax token. */
      DEFAULT,
      /** Decompiler error marker token. */
      ERROR,
      /** Special compiler or p-code annotation token. */
      SPECIAL
    }
  }

  /** Output representation format for decompiled functions. */
  public enum Format {
    /** Plain C source text only. */
    TEXT,
    /** Flat syntax token stream only. */
    TOKENS,
    /** C source text paired with line-oriented positioned tokens. */
    DOCUMENT
  }
}
