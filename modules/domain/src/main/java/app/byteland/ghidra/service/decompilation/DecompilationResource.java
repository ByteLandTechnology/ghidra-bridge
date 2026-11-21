package app.byteland.ghidra.service.decompilation;

import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import java.util.List;
import java.util.Objects;

/**
 * Holds function decompilation output in text, token, or document format.
 *
 * @param entry function entry point address
 * @param name function name
 * @param format output representation format
 * @param completed true when decompilation finished within limits
 * @param elapsedMs elapsed decompilation time in milliseconds
 * @param c rendered C source text when present
 * @param tokens flat token list for token format
 * @param lines structured GUI lines for document format
 * @param comments listing comments inside the function body
 * @param commentsComplete true when all function comments were collected
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
  /** Validates format fields and copies list components. */
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
   * Returns an immutable copy of the flat token list, or null when absent.
   *
   * @return immutable token list or null
   */
  @Override
  public List<Token> tokens() {
    return immutableCopyOrNull(tokens);
  }

  /**
   * Returns an immutable copy of the document lines, or null when absent.
   *
   * @return immutable line list or null
   */
  @Override
  public List<Line> lines() {
    return immutableCopyOrNull(lines);
  }

  /**
   * Returns an immutable copy of collected function comments, or null when absent.
   *
   * @return immutable comment list or null
   */
  @Override
  public List<CommentResource> comments() {
    return immutableCopyOrNull(comments);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * One GUI line with zero-based UTF-16 column offsets and indentation.
   *
   * @param number one-based line number
   * @param indent indentation level
   * @param tokens tokens placed on this line
   */
  public record Line(int number, int indent, List<LocatedToken> tokens) {
    /** Copies line tokens into an immutable list. */
    public Line {
      tokens = List.copyOf(tokens);
    }
  }

  /**
   * Decompiler token with column offsets and separate token and cursor addresses.
   *
   * @param kind syntax token classification
   * @param text rendered token text
   * @param start inclusive zero-based UTF-16 start column
   * @param end exclusive zero-based UTF-16 end column
   * @param address minimum instruction address associated with the token
   * @param maxAddress maximum instruction address associated with the token
   * @param locationAddress GUI cursor location address
   * @param codeUnitAddress listing code unit address
   * @param symbol resolved symbol metadata when applicable
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
   * Decompiler syntax token and optional instruction address.
   *
   * @param kind syntax token classification
   * @param text rendered token text
   * @param address optional instruction address
   */
  public record Token(Kind kind, String text, String address) {
    /** Validates required token kind and text. */
    public Token {
      if (kind == null) throw new IllegalArgumentException("token kind is required");
      if (text == null) throw new IllegalArgumentException("token text is required");
    }

    /** Syntax classification for decompiler tokens. */
    public enum Kind {
      /** Language keyword token. */
      KEYWORD,
      /** Comment token. */
      COMMENT,
      /** Data type name token. */
      TYPE,
      /** Function name token. */
      FUNCTION,
      /** Local variable token. */
      VARIABLE,
      /** Constant literal token. */
      CONSTANT,
      /** Function parameter token. */
      PARAMETER,
      /** Global variable token. */
      GLOBAL,
      /** Unclassified punctuation or operator token. */
      DEFAULT,
      /** Decompiler error marker token. */
      ERROR,
      /** Special directive or annotation token. */
      SPECIAL
    }
  }

  /** Output formats for function decompilation responses. */
  public enum Format {
    /** Plain C source text only. */
    TEXT,
    /** Flat decompiler token stream only. */
    TOKENS,
    /** C source text paired with structured line and token spans. */
    DOCUMENT
  }
}
