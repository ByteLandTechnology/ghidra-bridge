package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
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
    boolean preserveOffsets = patch.preserveOffsets();
    StructureAccess access = new StructureAccess(structure, preserveOffsets);
    remove(structure, patch.removeFields(), preserveOffsets);
    CompositeFieldMutations.renameFields(access, patch.renameFields(), resolver);
    CompositeFieldMutations.updateFields(access, patch.updateFields(), resolver);
    if (patch.addFields() != null) {
      for (DataTypePatch.CompositeField field : patch.addFields()) {
        add(structure, field, preserveOffsets, resolver);
      }
    }
  }

  private static void add(
      Structure structure,
      DataTypePatch.CompositeField field,
      boolean preserveOffsets,
      Function<DataTypeReference, DataType> resolver) {
    String name =
        field.name() == null
            ? "field"
            : DataTypeMutationSupport.normalizedFieldName(field.name());
    String comment = DataTypeMutationSupport.normalizedComment(field.comment());
    DataType dataType = DataTypeMutationSupport.resolveFieldDataType(field.dataType(), resolver);
    int length = DataTypeMutationSupport.fieldLength(dataType, field.length(), null);
    if (field.offset() == null) {
      structure.add(dataType, length, name, comment);
    } else if (preserveOffsets && !structure.isPackingEnabled()) {
      int offset = field.offset();
      DataTypeMutationSupport.ensureNoDefinedOverlap(
          structure, offset, length, null, "patch.addFields");
      DataTypeMutationSupport.growToFit(structure, offset + length);
      structure.replaceAtOffset(offset, dataType, length, name, comment);
    } else {
      structure.insertAtOffset(field.offset(), dataType, length, name, comment);
    }
  }

  private static void remove(
      Structure structure,
      List<DataTypePatch.CompositeField> selectors,
      boolean preserveOffsets) {
    if (selectors == null) return;
    List<Integer> ordinals = new ArrayList<>();
    for (DataTypePatch.CompositeField selector : selectors) {
      ordinals.addAll(resolveOrdinals(structure, selector, preserveOffsets));
    }
    ordinals = ordinals.stream().distinct().sorted(Collections.reverseOrder()).toList();
    for (int ordinal : ordinals) {
      if (ordinal < 0 || ordinal >= structure.getNumComponents()) continue;
      if (preserveOffsets) {
        DataTypeComponent component = structure.getComponent(ordinal);
        if (!component.isUndefined() || structure.isPackingEnabled()) {
          structure.clearComponent(ordinal);
        }
      } else {
        structure.delete(ordinal);
      }
    }
  }

  private static List<Integer> resolveOrdinals(
      Structure structure, DataTypePatch.CompositeField selector, boolean preserveOffsets) {
    if (selector.offset() != null) {
      int offset = selector.offset();
      if (preserveOffsets) {
        DataTypeComponent component = structure.getComponentAt(offset);
        return component != null && component.getOffset() == offset
            ? List.of(component.getOrdinal())
            : List.of();
      }
      DataTypeComponent defined = structure.getDefinedComponentAtOrAfterOffset(offset);
      if (defined != null && defined.getOffset() == offset) {
        return List.of(defined.getOrdinal());
      }
      DataTypeComponent slot = structure.getComponentAt(offset);
      return slot != null && slot.isUndefined() && slot.getOffset() == offset
          ? List.of(slot.getOrdinal())
          : List.of();
    }
    if (selector.name() == null) {
      throw new IllegalArgumentException("struct field selector requires name or offset");
    }
    List<Integer> matches = new ArrayList<>();
    for (int index = 0; index < structure.getNumComponents(); index++) {
      DataTypeComponent component = structure.getComponent(index);
      if (selector.name().equals(component.getFieldName())) matches.add(component.getOrdinal());
    }
    return matches;
  }

  private record StructureAccess(Structure structure, boolean preserveOffsets)
      implements CompositeFieldMutations.CompositeAccess {
    @Override
    public CompositeFieldMutations.CompositeKind kind() {
      return CompositeFieldMutations.CompositeKind.STRUCT;
    }

    @Override
    public List<Integer> locate(DataTypePatch.CompositeField selector) {
      return resolveOrdinals(structure, selector, preserveOffsets);
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
      if (preserveOffsets && !structure.isPackingEnabled()) {
        int offset = component.getOffset();
        DataTypeMutationSupport.ensureNoDefinedOverlap(
            structure, offset, replacement.length(), component, "patch.updateFields");
        DataTypeMutationSupport.growToFit(structure, offset + replacement.length());
        structure.replaceAtOffset(
            offset,
            replacement.dataType(),
            replacement.length(),
            replacement.name(),
            replacement.comment());
      } else {
        structure.replace(
            component.getOrdinal(),
            replacement.dataType(),
            replacement.length(),
            replacement.name(),
            replacement.comment());
      }
    }
  }
}
