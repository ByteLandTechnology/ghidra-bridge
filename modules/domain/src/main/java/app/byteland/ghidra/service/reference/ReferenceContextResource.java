package app.byteland.ghidra.service.reference;

import java.util.Objects;

/**
 * Holds one reference with its optional call site and caller function summary.
 */
public record ReferenceContextResource(
    String from,
    String to,
    String type,
    int operandIndex,
    boolean primary,
    String sourceType,
    String callSite,
    CallerSummary caller) {
  public ReferenceContextResource {
    Objects.requireNonNull(from, "from");
    Objects.requireNonNull(to, "to");
    Objects.requireNonNull(type, "type");
  }

  /**
   * Summarizes the function whose body owns a reference source address.
   */
  public record CallerSummary(String entry, String name, String namespace, String demangledName) {
    public CallerSummary {
      Objects.requireNonNull(entry, "entry");
      Objects.requireNonNull(name, "name");
    }
  }
}
