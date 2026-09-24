package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.Comparator;

final class ReferenceDescriptions {
  private ReferenceDescriptions() {}

  static ReferenceResource describe(Reference reference) {
    return new ReferenceResource(
        AddressUtil.canonicalAddress(reference.getFromAddress()),
        AddressUtil.canonicalAddress(reference.getToAddress()),
        reference.getReferenceType().getName(),
        reference.getOperandIndex(),
        reference.isPrimary(),
        String.valueOf(reference.getSource()));
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
