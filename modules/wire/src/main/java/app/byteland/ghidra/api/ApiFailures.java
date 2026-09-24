package app.byteland.ghidra.api;

import app.byteland.ghidra.service.DomainException;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeoutException;

public final class ApiFailures {
  private static final char ARRAY_INDEX_END = ']';

  private ApiFailures() {}

  public static Failure normalize(Throwable failure) {
    if (failure instanceof ApiException error) {
      return new Failure(error.status(), error.error());
    }
    if (failure instanceof DomainException domain) {
      return failure(domain.status(), domain.code(), failure, pointer(domain.target()));
    }
    if (failure instanceof IllegalArgumentException) {
      return failure(400, "invalid_request", failure, null);
    }
    if (failure instanceof NoSuchElementException) {
      return failure(404, "resource_not_found", failure, null);
    }
    if (failure instanceof SecurityException) {
      return fixedFailure(403, "access_forbidden", "Access forbidden");
    }
    if (failure instanceof TimeoutException) {
      return failure(408, "operation_timed_out", failure, null);
    }
    return fixedFailure(500, "internal_error", "Internal error");
  }

  private static Failure failure(int status, String code, Throwable failure, String target) {
    return new Failure(
        status, new BridgeError(status, code, outerMessage(failure), target, Map.of()));
  }

  private static Failure fixedFailure(int status, String code, String message) {
    return new Failure(status, new BridgeError(status, code, message, null, Map.of()));
  }

  private static String outerMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? failure.getClass().getName() : message;
  }

  private static String pointer(String target) {
    if (target == null || target.isBlank() || target.startsWith("/")) return target;
    StringBuilder result = new StringBuilder();
    StringBuilder segment = new StringBuilder();
    for (int index = 0; index < target.length(); index++) {
      char character = target.charAt(index);
      if (character == '.' || character == '[' || character == '/') {
        appendPointerSegment(result, segment);
      } else if (character != ARRAY_INDEX_END) {
        segment.append(character);
      }
    }
    appendPointerSegment(result, segment);
    return result.toString();
  }

  private static void appendPointerSegment(StringBuilder result, StringBuilder segment) {
    if (!segment.isEmpty()) {
      result.append('/').append(snakeCase(segment.toString()));
      segment.setLength(0);
    }
  }

  private static String snakeCase(String value) {
    StringBuilder result = new StringBuilder();
    for (int index = 0; index < value.length(); index++) {
      char character = value.charAt(index);
      if (Character.isUpperCase(character)) {
        if (!result.isEmpty() && result.charAt(result.length() - 1) != '_') result.append('_');
        result.append(Character.toLowerCase(character));
      } else {
        result.append(character);
      }
    }
    return result.toString();
  }

  public record Failure(int status, BridgeError error) {}
}
