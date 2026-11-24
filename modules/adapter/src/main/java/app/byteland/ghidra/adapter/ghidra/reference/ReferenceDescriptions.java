package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.Comparator;

final class ReferenceDescriptions {
  private ReferenceDescriptions() {}

  static ReferenceResource describe(Reference reference) {
    return describe(reference, null, null);
  }

  static ReferenceResource describe(
      Reference reference, Address anchor, String canonicalAnchor) {
    return new ReferenceResource(
        canonicalEndpoint(reference.getFromAddress(), anchor, canonicalAnchor),
        canonicalEndpoint(reference.getToAddress(), anchor, canonicalAnchor),
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
