package app.byteland.ghidra.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Reports an HTTP 409 conflict when a bare symbol or data type matches multiple definitions.
 */
public final class AmbiguousTargetException extends RuntimeException implements DomainException {
  private static final long serialVersionUID = 1L;
  private static final int CONFLICT_STATUS = 409;

  private final String code;
  private final String target;
  private final Map<String, Object> details;

  public AmbiguousTargetException(
      String code, String message, String target, List<String> candidates) {
    super(Objects.requireNonNull(message, "message"));
    this.code = Objects.requireNonNull(code, "code");
    this.target = target;
    Map<String, Object> map = new LinkedHashMap<>();
    if (candidates != null && !candidates.isEmpty()) {
      map.put("candidates", List.copyOf(candidates));
    }
    this.details = Collections.unmodifiableMap(map);
  }

  @Override
  public int status() {
    return CONFLICT_STATUS;
  }

  @Override
  public String code() {
    return code;
  }

  @Override
  public String target() {
    return target;
  }

  @Override
  public Map<String, Object> details() {
    return details;
  }
}
