package app.byteland.ghidra.service.program;

import app.byteland.ghidra.service.DomainException;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validates and evaluates case-insensitive text and regular expression filters.
 */
public final class ProgramTextMatcher {
  public static final int MAX_REGEX_LENGTH = 256;
  private static final int MAX_EVALUATION_STEPS = 10_000;

  private final String substringLower;
  private final Pattern regexPattern;
  private final String target;

  private ProgramTextMatcher(String substringLower, Pattern regexPattern, String target) {
    this.substringLower = substringLower;
    this.regexPattern = regexPattern;
    this.target = target;
  }

  /** Builds a matcher from optional text and explicit regular expression inputs. */
  public static ProgramTextMatcher compile(
      String textValue, boolean textIsRegex, String explicitRegex, String fieldName) {
    String textTarget = "/filter/" + fieldName;
    String regexTarget = "/filter/" + fieldName + "_regex";
    if (explicitRegex != null && textValue != null && textIsRegex) {
      throw new InvalidFilterPatternException(
          "do not combine " + fieldName + "_regex with " + fieldName + " when regex is true",
          regexTarget);
    }
    Pattern compiled = null;
    String compiledTarget = textTarget;
    if (explicitRegex != null) {
      compiled = compilePattern(explicitRegex, regexTarget);
      compiledTarget = regexTarget;
    } else if (textIsRegex && textValue != null) {
      compiled = compilePattern(textValue, textTarget);
    }
    String substring =
        !textIsRegex && textValue != null && !textValue.isEmpty()
            ? textValue.toLowerCase(Locale.ROOT)
            : null;
    if (compiled == null && substring == null) {
      return null;
    }
    return new ProgramTextMatcher(substring, compiled, compiledTarget);
  }

  /** Returns true when the candidate text satisfies all configured criteria. */
  public boolean matches(String candidate) {
    String safe = candidate == null ? "" : candidate;
    if (substringLower != null && !safe.toLowerCase(Locale.ROOT).contains(substringLower)) {
      return false;
    }
    if (regexPattern == null) {
      return true;
    }
    BoundedCharSequence bounded = new BoundedCharSequence(safe, MAX_EVALUATION_STEPS, target);
    return regexPattern.matcher(bounded).find();
  }

  private static Pattern compilePattern(String rawPattern, String target) {
    if (rawPattern.length() > MAX_REGEX_LENGTH) {
      throw new InvalidFilterPatternException(
          "regular expression length exceeds " + MAX_REGEX_LENGTH + " characters", target);
    }
    try {
      return Pattern.compile(rawPattern, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    } catch (PatternSyntaxException syntaxError) {
      InvalidFilterPatternException failure =
          new InvalidFilterPatternException(
              "invalid regular expression: " + syntaxError.getDescription(), target);
      failure.initCause(syntaxError);
      throw failure;
    }
  }

  /**
   * Reports an invalid or overly complex regular expression filter with HTTP status 400.
   */
  public static final class InvalidFilterPatternException extends IllegalArgumentException
      implements DomainException {
    private static final long serialVersionUID = 1L;
    private final String errorTarget;

    public InvalidFilterPatternException(String message, String errorTarget) {
      super(message);
      this.errorTarget = errorTarget;
    }

    @Override
    public int status() {
      return 400;
    }

    @Override
    public String code() {
      return "invalid_regex";
    }

    @Override
    public String target() {
      return errorTarget;
    }
  }

  private static final class BoundedCharSequence implements CharSequence {
    private final String delegate;
    private final int maxSteps;
    private final String target;
    private int steps;

    private BoundedCharSequence(String delegate, int maxSteps, String target) {
      this.delegate = delegate;
      this.maxSteps = maxSteps;
      this.target = target;
    }

    @Override
    public int length() {
      return delegate.length();
    }

    @Override
    public char charAt(int index) {
      steps++;
      if (steps > maxSteps) {
        throw new InvalidFilterPatternException(
            "regular expression evaluation step limit exceeded", target);
      }
      return delegate.charAt(index);
    }

    @Override
    public CharSequence subSequence(int start, int end) {
      return new BoundedCharSequence(delegate.substring(start, end), maxSteps - steps, target);
    }

    @Override
    public String toString() {
      return delegate;
    }
  }
}
