package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeComponentImpl;
import ghidra.program.model.data.Structure;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

final class StructMutations {
  private StructMutations() {}

  static void edit(
      Structure structure,
      DataTypePatch.Struct patch,
      Function<DataTypeReference, DataType> resolver) {
    StructureAccess access = new StructureAccess(structure);
    remove(structure, patch.removeFields());
    CompositeFieldMutations.renameFields(access, patch.renameFields(), resolver);
    CompositeFieldMutations.updateFields(access, patch.updateFields(), resolver);
    if (patch.addFields() != null) {
      for (DataTypePatch.CompositeField field : patch.addFields()) add(structure, field, resolver);
    }
  }

  private static void add(
      Structure structure,
      DataTypePatch.CompositeField field,
      Function<DataTypeReference, DataType> resolver) {
    String name = field.name() == null ? "field" : field.name();
    DataType dataType = DataTypeMutationSupport.resolveFieldDataType(field.dataType(), resolver);
    int length = DataTypeMutationSupport.fieldLength(dataType, field.length(), null);
    String comment = DataTypeMutationSupport.normalizeComment(field.comment());
    if (field.offset() == null) {
      structure.add(dataType, length, name, comment);
      return;
    }
    int offset = field.offset();
    if (structure.isPackingEnabled()) {
      structure.insertAtOffset(offset, dataType, length, name, comment);
      return;
    }
    int effectiveLength = effectiveComponentLength(structure, dataType, length);
    ensureUnpackedRangeAvailable(structure, offset, effectiveLength, -1);
    if (effectiveLength == 0 && offset == unpackedLength(structure)) {
      structure.insertAtOffset(offset, dataType, 0, name, comment);
      return;
    }
    ensureUnpackedCapacity(structure, offset, Math.max(effectiveLength, 1));
    structure.replaceAtOffset(offset, dataType, effectiveLength, name, comment);
  }

  private static void remove(Structure structure, List<DataTypePatch.CompositeField> selectors) {
    if (selectors == null) return;
    List<Integer> ordinals = new ArrayList<>();
    for (DataTypePatch.CompositeField selector : selectors) {
      ordinals.addAll(resolveOrdinals(structure, selector));
    }
    ordinals = ordinals.stream().distinct().sorted(Collections.reverseOrder()).toList();
    for (int ordinal : ordinals) {
      if (ordinal >= 0 && ordinal < structure.getNumComponents()) {
        if (structure.isPackingEnabled()) structure.delete(ordinal);
        else structure.clearComponent(ordinal);
      }
    }
  }

  private static List<Integer> resolveOrdinals(
      Structure structure, DataTypePatch.CompositeField selector) {
    if (selector.offset() != null) {
      DataTypeComponent component = structure.getComponentAt(selector.offset());
      return component != null ? List.of(component.getOrdinal()) : List.of();
    }
    if (selector.name() == null) {
      throw new IllegalArgumentException("struct field selector requires name or offset");
    }
    List<Integer> matches = new ArrayList<>();
    for (DataTypeComponent component : structure.getDefinedComponents()) {
      if (selector.name().equals(component.getFieldName())) matches.add(component.getOrdinal());
    }
    return matches;
  }

  private static int effectiveComponentLength(
      Structure structure, DataType dataType, int requestedLength) {
    DataType cloned =
        structure.getDataTypeManager() == null
            ? dataType
            : dataType.clone(structure.getDataTypeManager());
    return DataTypeComponentImpl.getPreferredComponentLength(cloned, requestedLength);
  }

  private static int unpackedLength(Structure structure) {
    return structure.isZeroLength() ? 0 : structure.getLength();
  }

  private static void ensureUnpackedRangeAvailable(
      Structure structure, int offset, int length, int ignoredOrdinal) {
    if (offset < 0) throw new IllegalArgumentException("offset must not be negative");
    long end = (long) offset + length;
    if (end > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("struct field exceeds maximum structure size");
    }
    for (DataTypeComponent defined : structure.getDefinedComponents()) {
      if (defined.getOrdinal() == ignoredOrdinal) continue;
      int definedOffset = defined.getOffset();
      long definedEnd = (long) definedOffset + defined.getLength();
      boolean overlaps =
          defined.getLength() == 0
              ? (length == 0
                  ? definedOffset == offset
                  : (offset < definedOffset && definedOffset < end))
              : (length == 0
                  ? (definedOffset <= offset && offset < definedEnd)
                  : (offset < definedEnd && definedOffset < end));
      if (overlaps) {
        throw new IllegalArgumentException(
            "struct field at offset "
                + offset
                + " overlaps defined component at offset "
                + definedOffset);
      }
    }
  }

  private static void ensureUnpackedCapacity(Structure structure, int offset, int length) {
    long end = (long) offset + length;
    if (end > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("struct field exceeds maximum structure size");
    }
    int currentLength = unpackedLength(structure);
    if (end > currentLength) {
      structure.growStructure((int) end - currentLength);
    }
  }

  private record StructureAccess(Structure structure)
      implements CompositeFieldMutations.CompositeAccess {
    @Override
    public CompositeFieldMutations.CompositeKind kind() {
      return CompositeFieldMutations.CompositeKind.STRUCT;
    }

    @Override
    public List<Integer> locate(DataTypePatch.CompositeField selector) {
      return resolveOrdinals(structure, selector);
    }

    @Override
    public int componentCount() {
      return structure.getNumComponents();
    }

    @Override
    public DataTypeComponent component(int ordinal) {
      return structure.getComponent(ordinal);
    }

    @Override
    public void replace(
        DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {
      int ordinal = component.getOrdinal();
      int offset = component.getOffset();
      int length = replacement.length();
      if (!structure.isPackingEnabled()) {
        length = effectiveComponentLength(structure, replacement.dataType(), replacement.length());
        ensureUnpackedRangeAvailable(structure, offset, length, ordinal);
        ensureUnpackedCapacity(structure, offset, Math.max(length, 1));
      }
      structure.replace(
          ordinal,
          replacement.dataType(),
          length,
          replacement.name(),
          replacement.comment());
    }
  }
}
