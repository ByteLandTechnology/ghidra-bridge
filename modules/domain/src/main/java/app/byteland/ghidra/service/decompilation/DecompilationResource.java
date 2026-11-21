package app.byteland.ghidra.service.decompilation;

import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import java.util.List;
import java.util.Objects;

/**
 * Decompiled output of a Ghidra function in text, token, or structured document format.
 *
 * @param entry canonical function entry-point address
 * @param name function name
 * @param format requested output format
 * @param completed {@code true} if decompilation succeeded
 * @param elapsedMs decompilation wall-clock duration in milliseconds
 * @param c rendered C source text for {@link Format#TEXT} and {@link Format#DOCUMENT}
 * @param tokens flat token list for {@link Format#TOKENS}
 * @param lines structured GUI lines for {@link Format#DOCUMENT}
 * @param comments optional program comments inside the function body
 * @param commentsComplete {@code true} when all function comments were collected, or {@code null}
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
  /** Validates format-specific fields and copies collections into immutable lists. */
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
   * Returns the flat syntax token list for {@link Format#TOKENS} output.
   *
   * @return immutable token list, or {@code null}
   */
  @Override
  public List<Token> tokens() {
    return immutableCopyOrNull(tokens);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * One GUI line. Columns use zero-based UTF-16 offsets, with indentation.
   *
   * @param number one-based line number
   * @param indent indentation level
   * @param tokens located tokens on this line
   */
  public record Line(int number, int indent, List<LocatedToken> tokens) {
    /** Copies line tokens into an immutable list. */
    public Line {
      tokens = List.copyOf(tokens);
    }
  }

  /**
   * Token with UTF-16 column span, address metadata, and optional resolved symbol.
   *
   * <p>The token address and the GUI cursor address have separate meanings.
   *
   * @param kind token syntax category
   * @param text rendered token text
   * @param start inclusive zero-based UTF-16 start column
   * @param end exclusive zero-based UTF-16 end column
   * @param address minimum instruction address associated with the token, or {@code null}
   * @param maxAddress maximum instruction address associated with the token, or {@code null}
   * @param locationAddress GUI navigation target address, or {@code null}
   * @param codeUnitAddress code unit address for comments, or {@code null}
   * @param symbol resolved program symbol for the token, or {@code null}
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
   * Flat decompiler token with syntax category and optional instruction address.
   *
   * @param kind token syntax category
   * @param text rendered token text
   * @param address associated canonical instruction address, or {@code null}
   */
  public record Token(Kind kind, String text, String address) {
    /** Validates that token kind and text are non-null. */
    public Token {
      if (kind == null) throw new IllegalArgumentException("token kind is required");
      if (text == null) throw new IllegalArgumentException("token text is required");
    }

    /**
     * Syntax classification of a decompiler token.
     */
    public enum Kind {
      /** C language keyword or operator token. */
      KEYWORD,
      /** Comment token. */
      COMMENT,
      /** Data type name token. */
      TYPE,
      /** Function identifier token. */
      FUNCTION,
      /** Local variable identifier token. */
      VARIABLE,
      /** Literal constant token. */
      CONSTANT,
      /** Function parameter identifier token. */
      PARAMETER,
      /** Global variable identifier token. */
      GLOBAL,
      /** Default punctuation or whitespace token. */
      DEFAULT,
      /** Decompiler error marker token. */
      ERROR,
      /** Special compiler or intrinsic token. */
      SPECIAL
    }
  }

  /**
   * Output representation mode for decompiled functions.
   */
  public enum Format {
    /** Plain C source string only. */
    TEXT,
    /** Flat list of syntax tokens only. */
    TOKENS,
    /** Full C source with line-indexed located tokens and optional comments. */
    DOCUMENT
  }
}
