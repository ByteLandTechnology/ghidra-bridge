package app.byteland.ghidra;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class JsonParser {
  // Limit the JSON structure depth to prevent call stack overflow.
  private static final int MAX_NESTING_DEPTH = 500;

  private static final char STRING_QUOTE = '"';
  private static final char ESCAPE_PREFIX = '\\';
  private static final char FIRST_NON_CONTROL_CHARACTER = 0x20;

  private final String input;
  private int index;
  private int depth;

  JsonParser(String input) {
    this.input = input == null ? "" : input;
  }

  Object parseValue() {
    skipWhitespace();
    if (isAtEnd()) {
      throw new IllegalArgumentException("Unexpected end of JSON");
    }
    char ch = input.charAt(index);
    return switch (ch) {
      case '{' -> parseObject();
      case '[' -> parseArray();
      case STRING_QUOTE -> parseString();
      case 't' -> parseLiteral("true", true);
      case 'f' -> parseLiteral("false", false);
      case 'n' -> parseLiteral("null", null);
      default -> parseNumber();
    };
  }

  int currentIndex() {
    return index;
  }

  void skipWhitespace() {
    while (!isAtEnd()) {
      char ch = input.charAt(index);
      if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
        index++;
      } else {
        break;
      }
    }
  }

  boolean isAtEnd() {
    return index >= input.length();
  }

  private Map<String, Object> parseObject() {
    expect('{');
    enterNesting();
    try {
      Map<String, Object> map = new LinkedHashMap<>();
      skipWhitespace();
      if (peek('}')) {
        expect('}');
        return map;
      }
      while (true) {
        skipWhitespace();
        String key = parseString();
        skipWhitespace();
        expect(':');
        Object value = parseValue();
        if (map.containsKey(key)) {
          throw new IllegalArgumentException("Duplicate object field: " + key);
        }
        map.put(key, value);
        skipWhitespace();
        if (peek('}')) {
          expect('}');
          return map;
        }
        expect(',');
      }
    } finally {
      exitNesting();
    }
  }

  private List<Object> parseArray() {
    expect('[');
    enterNesting();
    try {
      List<Object> values = new ArrayList<>();
      skipWhitespace();
      if (peek(']')) {
        expect(']');
        return values;
      }
      while (true) {
        values.add(parseValue());
        skipWhitespace();
        if (peek(']')) {
          expect(']');
          return values;
        }
        expect(',');
      }
    } finally {
      exitNesting();
    }
  }

  private void enterNesting() {
    depth++;
    if (depth > MAX_NESTING_DEPTH) {
      throw new IllegalArgumentException(
          "JSON nesting exceeds maximum depth of " + MAX_NESTING_DEPTH);
    }
  }

  private void exitNesting() {
    depth--;
  }

  private String parseString() {
    expect(STRING_QUOTE);
    int start = index;
    int runStart = start;
    StringBuilder builder = null;
    int length = input.length();
    while (index < length) {
      char ch = input.charAt(index);
      index++;
      if (ch == STRING_QUOTE) {
        int quoteIndex = index - 1;
        if (builder == null) {
          return input.substring(start, quoteIndex);
        }
        if (quoteIndex > runStart) {
          builder.append(input, runStart, quoteIndex);
        }
        return builder.toString();
      }
      if (ch == ESCAPE_PREFIX) {
        int escapeIndex = index - 1;
        if (isAtEnd()) {
          throw new IllegalArgumentException("Invalid escape at end of input");
        }
        if (builder == null) {
          builder = new StringBuilder(estimateStringCapacity(start, escapeIndex));
        }
        if (escapeIndex > runStart) {
          builder.append(input, runStart, escapeIndex);
        }
        char escaped = input.charAt(index);
        index++;
        switch (escaped) {
          case STRING_QUOTE, ESCAPE_PREFIX, '/' -> builder.append(escaped);
          case 'b' -> builder.append('\b');
          case 'f' -> builder.append('\f');
          case 'n' -> builder.append('\n');
          case 'r' -> builder.append('\r');
          case 't' -> builder.append('\t');
          case 'u' -> {
            if (index + 4 > length) {
              throw new IllegalArgumentException("Invalid unicode escape");
            }
            builder.append((char) HexFormat.fromHexDigits(input, index, index + 4));
            index += 4;
          }
          default -> throw new IllegalArgumentException("Unsupported escape: \\" + escaped);
        }
        runStart = index;
        continue;
      }
      if (ch < FIRST_NON_CONTROL_CHARACTER) {
        throw new IllegalArgumentException("Unescaped control character in string");
      }
    }
    throw new IllegalArgumentException("Unterminated string");
  }

  private int estimateStringCapacity(int start, int firstEscape) {
    int searchFrom = Math.min(firstEscape + 2, input.length());
    int quote = input.indexOf(STRING_QUOTE, searchFrom);
    for (int hops = 0; quote >= 0 && hops < 8 && isEscapedQuote(start, quote); hops++) {
      quote = input.indexOf(STRING_QUOTE, quote + 1);
    }
    if (quote < 0) {
      return Math.max(16, input.length() - start);
    }
    return Math.max(16, quote - start);
  }

  private boolean isEscapedQuote(int start, int quoteIndex) {
    int backslashes = 0;
    for (int i = quoteIndex - 1; i >= start && input.charAt(i) == ESCAPE_PREFIX; i--) {
      backslashes++;
    }
    return (backslashes & 1) == 1;
  }

  private Object parseNumber() {
    int start = index;
    if (peekRaw('-')) index++;
    if (isAtEnd()) throw invalidNumber(start);
    if (peekRaw('0')) {
      index++;
      if (!isAtEnd() && isDigit(input.charAt(index))) throw invalidNumber(start);
    } else {
      if (!isNonZeroDigit(input.charAt(index))) throw invalidNumber(start);
      while (!isAtEnd() && isDigit(input.charAt(index))) index++;
    }
    if (peekRaw('.')) {
      index++;
      int fractionStart = index;
      while (!isAtEnd() && isDigit(input.charAt(index))) index++;
      if (index == fractionStart) throw invalidNumber(start);
    }
    if (peekRaw('e') || peekRaw('E')) {
      index++;
      if (peekRaw('+') || peekRaw('-')) index++;
      int exponentStart = index;
      while (!isAtEnd() && isDigit(input.charAt(index))) index++;
      if (index == exponentStart) throw invalidNumber(start);
    }
    String token = input.substring(start, index);
    if (token.contains(".") || token.contains("e") || token.contains("E")) {
      double value = Double.parseDouble(token);
      if (!Double.isFinite(value)) throw invalidNumber(start);
      return value;
    }
    try {
      return Integer.parseInt(token);
    } catch (NumberFormatException ignored) {
      return Long.parseLong(token);
    }
  }

  private boolean peekRaw(char expected) {
    return !isAtEnd() && input.charAt(index) == expected;
  }

  private static boolean isDigit(char value) {
    return value >= '0' && value <= '9';
  }

  private static boolean isNonZeroDigit(char value) {
    return value >= '1' && value <= '9';
  }

  private static IllegalArgumentException invalidNumber(int index) {
    return new IllegalArgumentException("Invalid JSON number at index " + index);
  }

  private Object parseLiteral(String literal, Object value) {
    if (input.startsWith(literal, index)) {
      index += literal.length();
      return value;
    }
    throw new IllegalArgumentException("Expected " + literal + " at index " + index);
  }

  private void expect(char expected) {
    skipWhitespace();
    if (isAtEnd() || input.charAt(index) != expected) {
      throw new IllegalArgumentException("Expected '" + expected + "' at index " + index);
    }
    index++;
  }

  private boolean peek(char expected) {
    skipWhitespace();
    return !isAtEnd() && input.charAt(index) == expected;
  }
}
