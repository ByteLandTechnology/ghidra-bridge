package app.byteland.ghidra.mcp;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Objects;
import java.util.function.Consumer;

final class RequestLog {
  private static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ISO_OFFSET_DATE_TIME;
  private static final int CAUSE_LIMIT = 160;
  private static final int FIXED_LINE_CAPACITY = 64;

  private final long startedAtNanos = System.nanoTime();
  private final Consumer<String> sink;
  private String jsonRpcId = "-";
  private String requestMethod = "-";
  private String toolName = "-";
  private String outcome = "ok";
  private int httpStatus = 200;
  private String failureCause;

  RequestLog() {
    this(RequestLog::discard);
  }

  RequestLog(Consumer<String> sink) {
    this.sink = Objects.requireNonNull(sink, "sink");
  }

  RequestLog id(Object value) {
    if (value != null) {
      this.jsonRpcId = escapeSingleLine(String.valueOf(value));
    }
    return this;
  }

  RequestLog method(String value) {
    if (value != null) {
      this.requestMethod = escapeSingleLine(value);
    }
    return this;
  }

  RequestLog tool(String value) {
    if (value != null) {
      this.toolName = escapeSingleLine(value);
    }
    return this;
  }

  RequestLog status(int code) {
    this.httpStatus = code;
    return this;
  }

  RequestLog ok() {
    this.outcome = "ok";
    return this;
  }

  RequestLog error() {
    this.outcome = "error";
    return this;
  }

  RequestLog cause(String message) {
    if (message != null) {
      String escaped = escapeSingleLine(message);
      this.failureCause =
          escaped.length() > CAUSE_LIMIT ? escaped.substring(0, CAUSE_LIMIT) : escaped;
    }
    return this;
  }

  private static String escapeSingleLine(String value) {
    StringBuilder escaped = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\' -> escaped.append("\\\\");
        case '\r' -> escaped.append("\\r");
        case '\n' -> escaped.append("\\n");
        case '\t' -> escaped.append("\\t");
        default -> {
          if (Character.isISOControl(c) || c == '\u2028' || c == '\u2029') {
            appendUnicodeEscape(escaped, c);
          } else {
            escaped.append(c);
          }
        }
      }
    }
    return escaped.toString();
  }

  private static void appendUnicodeEscape(StringBuilder output, char value) {
    String hex = Integer.toHexString(value);
    output.append("\\u");
    for (int i = hex.length(); i < 4; i++) {
      output.append('0');
    }
    output.append(hex);
  }

  private static void discard(String ignored) {}

  void finish() {
    long elapsedMs = (System.nanoTime() - startedAtNanos) / 1_000_000L;
    int estimatedCapacity =
        FIXED_LINE_CAPACITY
            + jsonRpcId.length()
            + requestMethod.length()
            + toolName.length()
            + outcome.length()
            + (failureCause == null ? 0 : failureCause.length());
    StringBuilder line =
        new StringBuilder(estimatedCapacity)
            .append('[')
            .append(OffsetDateTime.now(ZoneOffset.UTC).format(TIMESTAMP))
            .append("] [ghidra-mcp] id=")
            .append(jsonRpcId)
            .append(' ')
            .append(requestMethod)
            .append(' ')
            .append(toolName)
            .append(' ')
            .append(outcome)
            .append(' ')
            .append(httpStatus)
            .append(' ')
            .append(elapsedMs)
            .append("ms");
    if (failureCause != null) {
      line.append(' ').append(failureCause);
    }
    sink.accept(line.toString());
  }
}
