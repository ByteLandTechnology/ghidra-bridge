package app.byteland.ghidra.service.decompilation;

import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import java.util.List;
import java.util.Objects;

/**
 * Decompiler output for a function in text, token, or structured document format.
 *
 * @param entry canonical function entry address
 * @param name function name
 * @param format output representation format
 * @param completed whether decompilation completed normally
 * @param elapsedMs elapsed decompilation time in milliseconds
 * @param c rendered C source text when requested by format
 * @param tokens flat token stream when requested by format
 * @param lines structured GUI lines when requested by format
 * @param comments optional program comments inside the function body
 * @param commentsComplete whether all comments in the function body were returned
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
  /** Validates format invariants and copies lists into immutable collections. */
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
   * Returns an immutable copy of the flat decompiler token stream.
   *
   * @return decompiler tokens or {@code null}
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
   * @param tokens located tokens on the line
   */
  public record Line(int number, int indent, List<LocatedToken> tokens) {
    /** Copies line tokens into an immutable list. */
    public Line {
      tokens = List.copyOf(tokens);
    }
  }

  /**
   * Located decompiler token on a structured line. The token address and the GUI cursor address
   * have separate meanings.
   *
   * @param kind token classification
   * @param text rendered token text
   * @param start inclusive UTF-16 start column
   * @param end exclusive UTF-16 end column
   * @param address primary instruction address associated with the token
   * @param maxAddress maximum instruction address associated with the token
   * @param locationAddress GUI location address for navigation
   * @param codeUnitAddress code unit address for comments or listing sync
   * @param symbol resolved program symbol when linked
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
   * Flat decompiler token entry.
   *
   * @param kind token classification
   * @param text rendered token text
   * @param address optional instruction address associated with the token
   */
  public record Token(Kind kind, String text, String address) {
    /** Validates required token kind and text fields. */
    public Token {
      if (kind == null) throw new IllegalArgumentException("token kind is required");
      if (text == null) throw new IllegalArgumentException("token text is required");
    }

    /** Classification of decompiler tokens. */
    public enum Kind {
      /** C language keyword. */
      KEYWORD,
      /** Comment token. */
      COMMENT,
      /** Data type name token. */
      TYPE,
      /** Function identifier token. */
      FUNCTION,
      /** Local or temporary variable token. */
      VARIABLE,
      /** Literal constant token. */
      CONSTANT,
      /** Function parameter token. */
      PARAMETER,
      /** Global variable or symbol token. */
      GLOBAL,
      /** Default punctuation or uncategorized token. */
      DEFAULT,
      /** Decompiler error marker token. */
      ERROR,
      /** Special syntax or annotation token. */
      SPECIAL
    }
  }

  /** Output representation format for function decompilation. */
  public enum Format {
    /** Rendered C text only. */
    TEXT,
    /** Flat token list only. */
    TOKENS,
    /** Rendered C text and structured located lines. */
    DOCUMENT
  }
}
