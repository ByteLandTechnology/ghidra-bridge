package app.byteland.ghidra.service;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Indicates an invalid or unparseable program address with optional target and active spaces.
 */
public class InvalidAddressException extends IllegalArgumentException implements DomainException {
  private static final long serialVersionUID = 1L;
  private final String target;
  private final transient Map<String, Object> details;

  public InvalidAddressException(String message, String target, List<String> validSpaces) {
    this(message, target, validSpaces, null);
  }

  public InvalidAddressException(
      String message, String target, List<String> validSpaces, String rawAddress) {
    super(message);
    this.target = target;
    List<String> sortedSpaces =
        validSpaces == null ? List.of() : validSpaces.stream().distinct().sorted().toList();
    Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("valid_spaces", sortedSpaces);
    if (rawAddress != null) {
      metadata.put("address", rawAddress);
    }
    this.details = Collections.unmodifiableMap(metadata);
  }

  @Override
  public int status() {
    return 400;
  }

  @Override
  public String code() {
    return "invalid_request";
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
