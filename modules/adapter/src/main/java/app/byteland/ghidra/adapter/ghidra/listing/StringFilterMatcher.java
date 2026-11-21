package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.service.listing.ListingService.StringQuery;
import app.byteland.ghidra.service.listing.StringResource;
import java.util.Locale;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validates string query filters before a scan and evaluates candidate strings within a deadline.
 */
final class StringFilterMatcher {
  static final int DEFAULT_CANDIDATE_MIN_LENGTH = 4;

  private final String normalizedQuery;
  private final Pattern regexPattern;
  private final boolean caseSensitive;
  private final Integer explicitMinLength;
  private final String normalizedEncoding;

  private StringFilterMatcher(
      String normalizedQuery,
      Pattern regexPattern,
      boolean caseSensitive,
      Integer explicitMinLength,
      String normalizedEncoding) {
    this.normalizedQuery = normalizedQuery;
    this.regexPattern = regexPattern;
    this.caseSensitive = caseSensitive;
    this.explicitMinLength = explicitMinLength;
    this.normalizedEncoding = normalizedEncoding;
  }

  static StringFilterMatcher compile(StringQuery query) {
    String substring =
        query.query() == null || query.query().isEmpty()
            ? null
            : (query.caseSensitive()
                ? query.query()
                : query.query().toLowerCase(Locale.ROOT));

    Pattern compiledRegex = null;
    if (query.regex() != null) {
      if (query.regex().isBlank()) {
        throw new IllegalArgumentException("regex must not be blank");
      }
      int flags = query.caseSensitive() ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
      try {
        compiledRegex = Pattern.compile(query.regex(), flags);
      } catch (PatternSyntaxException ex) {
        throw new IllegalArgumentException("invalid regex pattern: " + ex.getMessage(), ex);
      }
    }

    String encoding = null;
    if (query.encoding() != null) {
      if (query.encoding().isBlank()) {
        throw new IllegalArgumentException("encoding must not be blank");
      }
      encoding = normalizeEncodingToken(query.encoding());
      if (encoding.isEmpty()) {
        throw new IllegalArgumentException("encoding must not be blank");
      }
    }

    return new StringFilterMatcher(
        substring, compiledRegex, query.caseSensitive(), query.minLength(), encoding);
  }

  int minCandidateLength() {
    return explicitMinLength != null
        ? Math.max(1, explicitMinLength)
        : DEFAULT_CANDIDATE_MIN_LENGTH;
  }

  boolean matches(StringResource candidate, LongSupplier nanoTime, long deadlineNanos) {
    if (nanoTime.getAsLong() >= deadlineNanos) {
      throw new RegexTimeoutException();
    }
    String value = candidate.value() == null ? "" : candidate.value();
    if (explicitMinLength != null && value.length() < explicitMinLength) {
      return false;
    }
    if (normalizedEncoding != null && !encodingMatches(candidate.encoding(), normalizedEncoding)) {
      return false;
    }
    if (normalizedQuery != null) {
      String target = caseSensitive ? value : value.toLowerCase(Locale.ROOT);
      if (!target.contains(normalizedQuery)) {
        return false;
      }
    }
    if (regexPattern != null) {
      TimeoutCharSequence boundedValue =
          new TimeoutCharSequence(value, nanoTime, deadlineNanos);
      if (!regexPattern.matcher(boundedValue).find()) {
        return false;
      }
    }
    return true;
  }

  static String normalizeEncodingToken(String raw) {
    StringBuilder builder = new StringBuilder(raw.length());
    for (int index = 0; index < raw.length(); index++) {
      char ch = raw.charAt(index);
      if (Character.isLetterOrDigit(ch)) {
        builder.append(Character.toUpperCase(ch));
      }
    }
    String token = builder.toString();
    if ("ASCII".equals(token) || "ANSI".equals(token)) {
      return "USASCII";
    }
    if ("UNICODE".equals(token)) {
      return "UTF16";
    }
    return token;
  }

  private static boolean encodingMatches(String candidateEncoding, String requestedNormalized) {
    if (candidateEncoding == null) return false;
    String actual = normalizeEncodingToken(candidateEncoding);
    if (actual.equals(requestedNormalized)) {
      return true;
    }
    if ("UTF16".equals(requestedNormalized)) {
      return "UTF16LE".equals(actual) || "UTF16BE".equals(actual);
    }
    if ("UTF32".equals(requestedNormalized)) {
      return "UTF32LE".equals(actual) || "UTF32BE".equals(actual);
    }
    return false;
  }

  static final class RegexTimeoutException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    RegexTimeoutException() {
      super(null, null, true, false);
    }
  }

  static final class TimeoutCharSequence implements CharSequence {
    private final String delegate;
    private final LongSupplier nanoTime;
    private final long deadlineNanos;
    private int checks;

    TimeoutCharSequence(String delegate, LongSupplier nanoTime, long deadlineNanos) {
      this.delegate = delegate;
      this.nanoTime = nanoTime;
      this.deadlineNanos = deadlineNanos;
    }

    @Override
    public int length() {
      return delegate.length();
    }

    @Override
    public char charAt(int index) {
      if ((++checks & 0x3F) == 0 && nanoTime.getAsLong() >= deadlineNanos) {
        throw new RegexTimeoutException();
      }
      return delegate.charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
      return new TimeoutCharSequence(delegate.substring(start, end), nanoTime, deadlineNanos);
    }

    @Override
    public String toString() {
      return delegate;
    }
  }
}
