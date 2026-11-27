package app.byteland.ghidra.service.reference;

import app.byteland.ghidra.service.address.AddressResource;

public record ReferenceResource(
    String from,
    String to,
    String type,
    int operandIndex,
    boolean primary,
    String sourceType,
    AddressResource.FunctionSummary fromFunction,
    AddressResource.FunctionSummary toFunction) {
  public ReferenceResource(
      String from, String to, String type, int operandIndex, boolean primary, String sourceType) {
    this(from, to, type, operandIndex, primary, sourceType, null, null);
  }
}
