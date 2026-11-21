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

  static ReferenceResource describe(Reference reference, GhidraSession context) {
    FunctionManager functionManager =
        context == null ? null : context.currentProgram().getFunctionManager();
    return new ReferenceResource(
        AddressUtil.canonicalAddress(reference.getFromAddress()),
        AddressUtil.canonicalAddress(reference.getToAddress()),
        reference.getReferenceType().getName(),
        reference.getOperandIndex(),
        reference.isPrimary(),
        String.valueOf(reference.getSource()),
        functionSummary(functionManager, reference.getFromAddress()),
        functionSummary(functionManager, reference.getToAddress()));
  }

  private static AddressResource.FunctionSummary functionSummary(
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
    return new ReferenceCursorKey(
        AddressUtil.canonicalAddress(reference.getFromAddress()),
        AddressUtil.canonicalAddress(reference.getToAddress()),
        reference.getReferenceType().getName(),
        reference.getOperandIndex());
  }
}
