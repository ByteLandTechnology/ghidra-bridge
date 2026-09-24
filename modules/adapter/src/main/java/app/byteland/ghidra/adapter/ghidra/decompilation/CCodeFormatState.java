package app.byteland.ghidra.adapter.ghidra.decompilation;

final class CCodeFormatState {
  private static final char OPEN_PAREN = '(';
  private static final char CLOSE_PAREN = ')';
  private static final char OPEN_BRACE = '{';
  private static final char CLOSE_BRACE = '}';
  private static final char SEMICOLON = ';';
  private static final char COMMENT_MARKER = '/';
  private static final char COMMENT_BODY_END = '*';
  private static final char SPACE = ' ';
  private static final String ELSE_KEYWORD = "else";

  private int indent;
  private int parenDepth;
  private int position;
  private boolean atLineStart = true;
  private boolean inComment;

  boolean isInComment() {
    return inComment;
  }

  boolean hasRemaining(String raw) {
    return position < raw.length();
  }

  boolean startsBlockComment(String raw) {
    return currentChar(raw) == COMMENT_MARKER
        && position + 1 < raw.length()
        && raw.charAt(position + 1) == COMMENT_BODY_END;
  }

  void handleCommentChar(String raw, StringBuilder output) {
    char current = currentChar(raw);
    boolean beginsIndentedContent = atLineStart && !Character.isWhitespace(current);
    if (beginsIndentedContent) {
      appendIndent(output);
    }
    output.append(current);
    if (endsBlockComment(raw)) {
      output.append("/\n");
      inComment = false;
      atLineStart = true;
      position += 2;
      return;
    }
    if (beginsIndentedContent) {
      atLineStart = false;
    }
    position++;
  }

  void startBlockComment(StringBuilder output) {
    if (atLineStart) {
      appendIndent(output);
      atLineStart = false;
    }
    output.append("/*");
    inComment = true;
    position += 2;
  }

  void handleCodeChar(String raw, StringBuilder output) {
    char current = currentChar(raw);
    updateParenDepth(current);
    switch (current) {
      case OPEN_BRACE -> openBrace(output);
      case CLOSE_BRACE -> {
        closeBrace(raw, output);
        return;
      }
      case SEMICOLON -> {
        if (!handleSemicolon(output)) {
          appendChar(current, output);
        }
      }
      default -> appendChar(current, output);
    }
    position++;
  }

  private char currentChar(String raw) {
    return raw.charAt(position);
  }

  private boolean endsBlockComment(String raw) {
    return currentChar(raw) == COMMENT_BODY_END
        && position + 1 < raw.length()
        && raw.charAt(position + 1) == COMMENT_MARKER;
  }

  private void updateParenDepth(char current) {
    if (current == OPEN_PAREN) {
      parenDepth++;
    }
    if (current == CLOSE_PAREN) {
      parenDepth = Math.max(0, parenDepth - 1);
    }
  }

  private void openBrace(StringBuilder output) {
    trimTrailingWhitespace(output);
    output.append(" {\n");
    indent++;
    atLineStart = true;
  }

  private void closeBrace(String raw, StringBuilder output) {
    if (!atLineStart) {
      output.append('\n');
    }
    indent = Math.max(0, indent - 1);
    appendIndent(output);
    output.append(CLOSE_BRACE);
    int nextPosition = position + 1;
    while (nextPosition < raw.length() && raw.charAt(nextPosition) == SPACE) {
      nextPosition++;
    }
    if (raw.startsWith(ELSE_KEYWORD, nextPosition)) {
      output.append(SPACE);
      atLineStart = false;
      position = nextPosition;
      return;
    }
    output.append('\n');
    atLineStart = true;
    position++;
  }

  private boolean handleSemicolon(StringBuilder output) {
    if (parenDepth <= 0) {
      output.append(";\n");
      atLineStart = true;
      return true;
    }
    return false;
  }

  private void appendChar(char current, StringBuilder output) {
    if (atLineStart && !Character.isWhitespace(current)) {
      appendIndent(output);
      atLineStart = false;
    }
    output.append(current);
  }

  private void appendIndent(StringBuilder output) {
    output.append("  ".repeat(Math.max(0, indent)));
  }

  private void trimTrailingWhitespace(StringBuilder output) {
    while (output.length() > 0 && Character.isWhitespace(output.charAt(output.length() - 1))) {
      output.setLength(output.length() - 1);
    }
  }
}
