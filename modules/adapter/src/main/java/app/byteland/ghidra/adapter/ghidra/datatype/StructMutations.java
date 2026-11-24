package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
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
    StructureAccess access = new StructureAccess(structure);
    remove(structure, patch.removeFields());
    CompositeFieldMutations.renameFields(access, patch.renameFields(), resolver);
    CompositeFieldMutations.updateFields(access, patch.updateFields(), resolver);
    if (patch.addFields() != null) {
      for (int index = 0; index < patch.addFields().size(); index++) {
        add(structure, patch.addFields().get(index), index, resolver);
      }
    }
  }

  private static void add(
      Structure structure,
      DataTypePatch.CompositeField field,
      int index,
      Function<DataTypeReference, DataType> resolver) {
    if (structure.getNumDefinedComponents() >= DataTypeService.MAX_DEFINED_COMPONENTS) {
      throw new DataTypeMutationValidationException(
          "/patch/add_fields/" + index,
          "struct cannot exceed " + DataTypeService.MAX_DEFINED_COMPONENTS + " defined fields");
    }
    String name = field.name() == null ? "field" : field.name();
    DataType dataType = DataTypeMutationSupport.resolveFieldDataType(field.dataType(), resolver);
    int length = DataTypeMutationSupport.fieldLength(dataType, field.length(), null);
    int currentLength = currentByteLength(structure);
    int offset = field.offset() == null ? currentLength : field.offset();
    if (offset < 0) {
      throw new DataTypeMutationValidationException(
          "/patch/add_fields/" + index + "/offset", "struct field offset must not be negative");
    }
    String target =
        field.offset() != null
            ? "/patch/add_fields/" + index + "/offset"
            : "/patch/add_fields/" + index;
    validateEndOffset(offset, length, target);
    validateEndOffset(Math.max(offset, currentLength), length, target);
    if (field.offset() == null) structure.add(dataType, length, name, null);
    else structure.insertAtOffset(offset, dataType, length, name, null);
  }

  private static int currentByteLength(Structure structure) {
    int rawLength = structure.getLength();
    if (rawLength <= 0) return 0;
    if (rawLength == 1 && structure.isZeroLength()) return 0;
    return rawLength;
  }

  private static void validateEndOffset(int offset, int length, String target) {
    final int endOffset;
    try {
      endOffset = Math.addExact(offset, length);
    } catch (ArithmeticException overflow) {
      throw new DataTypeMutationValidationException(
          target,
          "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE,
          overflow);
    }
    if (endOffset > DataTypeService.MAX_STRUCT_SIZE) {
      throw new DataTypeMutationValidationException(
          target, "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE);
    }
  }

  private static void remove(Structure structure, List<DataTypePatch.CompositeField> selectors) {
    if (selectors == null) return;
    List<Integer> ordinals = new ArrayList<>();
    for (DataTypePatch.CompositeField selector : selectors) {
      ordinals.addAll(resolveOrdinals(structure, selector));
    }
    ordinals = ordinals.stream().distinct().sorted(Collections.reverseOrder()).toList();
    for (int ordinal : ordinals) {
      if (ordinal >= 0 && ordinal < structure.getNumComponents()) structure.delete(ordinal);
    }
  }

  private static List<Integer> resolveOrdinals(
      Structure structure, DataTypePatch.CompositeField selector) {
    if (selector.offset() != null) {
      DataTypeComponent component = structure.getDefinedComponentAtOrAfterOffset(selector.offset());
      return component != null && component.getOffset() == selector.offset()
          ? List.of(component.getOrdinal())
          : List.of();
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
      validateEndOffset(component.getOffset(), replacement.length(), "/patch/update_fields");
      structure.replace(
          component.getOrdinal(),
          replacement.dataType(),
          replacement.length(),
          replacement.name(),
          replacement.comment());
    }
  }
}
