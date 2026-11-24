package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.Comparator;

final class ReferenceDescriptions {
  private ReferenceDescriptions() {}

  static ReferenceResource describe(Reference reference) {
    return describe(reference, (FunctionManager) null, null, null, null);
  }

  static ReferenceResource describe(Reference reference, GhidraSession context) {
    return describe(reference, context, null, null);
  }

  static ReferenceResource describe(
      Reference reference, GhidraSession context, Address anchor, String canonicalAnchor) {
    FunctionManager functionManager =
        context == null ? null : context.currentProgram().getFunctionManager();
    return describe(
        reference,
        functionManager,
        anchor,
        canonicalAnchor,
        anchor == null ? null : functionSummary(functionManager, anchor));
  }

  static ReferenceResource describe(
      Reference reference,
      FunctionManager functionManager,
      Address anchor,
      String canonicalAnchor,
      AddressResource.FunctionSummary anchorFunction) {
    Address fromAddress = reference.getFromAddress();
    Address toAddress = reference.getToAddress();
    return new ReferenceResource(
        canonicalEndpoint(fromAddress, anchor, canonicalAnchor),
        canonicalEndpoint(toAddress, anchor, canonicalAnchor),
        reference.getReferenceType().getName(),
        reference.getOperandIndex(),
        reference.isPrimary(),
        String.valueOf(reference.getSource()),
        anchor != null && anchor.equals(fromAddress)
            ? anchorFunction
            : functionSummary(functionManager, fromAddress),
        anchor != null && anchor.equals(toAddress)
            ? anchorFunction
            : functionSummary(functionManager, toAddress));
  }

  static AddressResource.FunctionSummary functionSummary(
      FunctionManager functionManager, Address address) {
    if (functionManager == null || address == null) {
      return null;
    }
    Function function = functionManager.getFunctionContaining(address);
    if (function == null) {
      return null;
    }
    return new AddressResource.FunctionSummary(
        AddressUtil.canonicalAddress(function.getEntryPoint()), function.getName());
  }

  static Comparator<Reference> referenceComparator(boolean fromBody) {
    return Comparator.comparing(
            (Reference reference) ->
                fromBody ? reference.getToAddress() : reference.getFromAddress())
        .thenComparing(Reference::getToAddress)
        .thenComparingInt(Reference::getOperandIndex)
        .thenComparing(reference -> reference.getReferenceType().getName());
  }

  static Iterable<Reference> iterable(ReferenceIterator iterator) {
    return () -> iterator;
  }

  static ReferenceCursorKey referenceKey(Reference reference) {
    return referenceKey(reference, null, null);
  }

  static ReferenceCursorKey referenceKey(
      Reference reference, Address anchor, String canonicalAnchor) {
    return new ReferenceCursorKey(
        canonicalEndpoint(reference.getFromAddress(), anchor, canonicalAnchor),
        canonicalEndpoint(reference.getToAddress(), anchor, canonicalAnchor),
        reference.getReferenceType().getName(),
        reference.getOperandIndex());
  }

  private static String canonicalEndpoint(
      Address address, Address anchor, String canonicalAnchor) {
    return anchor != null && anchor.equals(address)
        ? canonicalAnchor
        : AddressUtil.canonicalAddress(address);
  }
}
