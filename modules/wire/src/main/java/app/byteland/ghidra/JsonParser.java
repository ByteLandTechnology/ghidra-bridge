package app.byteland.ghidra;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class JsonParser {
  // Limit nesting depth to prevent call stack overflow.
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
    StringBuilder builder = new StringBuilder();
    while (!isAtEnd()) {
      char ch = input.charAt(index);
      index++;
      if (ch == STRING_QUOTE) {
        return builder.toString();
      }
      if (ch == ESCAPE_PREFIX) {
        if (isAtEnd()) {
          throw new IllegalArgumentException("Invalid escape at end of input");
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
            if (index + 4 > input.length()) {
              throw new IllegalArgumentException("Invalid unicode escape");
            }
            String hex = input.substring(index, index + 4);
            builder.append((char) Integer.parseInt(hex, 16));
            index += 4;
          }
          default -> throw new IllegalArgumentException("Unsupported escape: \\" + escaped);
        }
        continue;
      }
      if (ch < FIRST_NON_CONTROL_CHARACTER) {
        throw new IllegalArgumentException("Unescaped control character in string");
      }
      builder.append(ch);
    }
    throw new IllegalArgumentException("Unterminated string");
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
