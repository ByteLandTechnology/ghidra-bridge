package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeComponentImpl;
import ghidra.program.model.data.Structure;
import java.util.List;
import java.util.function.Function;

final class StructMutations {
  private static final String PATCH_ADD_FIELDS_TARGET = "/patch/add_fields";
  private static final String RESOURCE_FIELDS_TARGET = "/resource/fields";
  private static final String PATCH_UPDATE_FIELDS_TARGET = "/patch/update_fields";

  private StructMutations() {}

  static void edit(
      Structure structure,
      DataTypePatch.Struct patch,
      Function<DataTypeReference, DataType> resolver) {
    CompositeFieldMutations.edit(
        new StructureAccess(structure, PATCH_ADD_FIELDS_TARGET),
        patch.removeFields(),
        patch.renameFields(),
        patch.updateFields(),
        patch.addFields(),
        resolver);
  }

  static void addInitialFields(
      Structure structure,
      List<DataTypePatch.CompositeField> fields,
      Function<DataTypeReference, DataType> resolver) {
    CompositeFieldMutations.addFields(
        new StructureAccess(structure, RESOURCE_FIELDS_TARGET), fields, resolver);
  }

  private static int effectiveComponentLength(
      Structure structure, DataType dataType, int requestedLength) {
    DataType cloned =
        structure.getDataTypeManager() == null
            ? dataType
            : dataType.clone(structure.getDataTypeManager());
    return DataTypeComponentImpl.getPreferredComponentLength(cloned, requestedLength);
  }

  private static int currentByteLength(Structure structure) {
    if (structure.isZeroLength()) return 0;
    return Math.max(structure.getLength(), 0);
  }

  private static void validateEndOffset(int offset, int length, String target) {
    final int endOffset;
    try {
      endOffset = Math.addExact(offset, length);
    } catch (ArithmeticException overflow) {
      throw new DataTypeMutationValidationException(
          target, "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE, overflow);
    }
    if (endOffset > DataTypeService.MAX_STRUCT_SIZE) {
      throw new DataTypeMutationValidationException(
          target, "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE);
    }
  }

  private static void ensureDefinedComponentCapacity(Structure structure, String target) {
    if (structure.getNumDefinedComponents() >= DataTypeService.MAX_DEFINED_COMPONENTS) {
      throw new DataTypeMutationValidationException(
          target,
          "struct cannot exceed " + DataTypeService.MAX_DEFINED_COMPONENTS + " defined fields");
    }
  }

  private static void ensureUnpackedRangeAvailable(
      Structure structure, int offset, int length, int ignoredOrdinal, String target) {
    validateEndOffset(offset, length, target);
    long end = (long) offset + length;
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
        throw new DataTypeMutationValidationException(
            target,
            "struct field at offset "
                + offset
                + " overlaps defined component at offset "
                + definedOffset);
      }
    }
  }

  private static void ensureUnpackedCapacity(
      Structure structure, int offset, int length, String target) {
    validateEndOffset(offset, length, target);
    int requiredLength = offset + length;
    int currentLength = currentByteLength(structure);
    if (requiredLength > currentLength) {
      structure.growStructure(requiredLength - currentLength);
    }
  }

  private record StructureAccess(Structure composite, String addTargetPrefix)
      implements CompositeFieldMutations.CompositeAccess {
    @Override
    public CompositeFieldMutations.CompositeKind kind() {
      return CompositeFieldMutations.CompositeKind.STRUCT;
    }

    @Override
    public List<Integer> locate(DataTypePatch.CompositeField selector) {
      if (selector.offset() != null) {
        if (selector.offset() < 0) return List.of();
        DataTypeComponent component = composite.getComponentAt(selector.offset());
        if (component == null) {
          DataTypeComponent defined =
              composite.getDefinedComponentAtOrAfterOffset(selector.offset());
          if (defined != null && defined.getOffset() == selector.offset()) {
            component = defined;
          }
        }
        return component != null ? List.of(component.getOrdinal()) : List.of();
      }
      if (selector.name() == null) {
        throw new IllegalArgumentException("struct field selector requires name or offset");
      }
      return CompositeFieldMutations.findOrdinalsByName(composite, selector.name());
    }

    @Override
    public void removeComponent(int ordinal) {
      if (composite.isPackingEnabled()) composite.delete(ordinal);
      else composite.clearComponent(ordinal);
    }

    @Override
    public void validateBeforeAdd(DataTypePatch.CompositeField field, int index) {
      ensureDefinedComponentCapacity(composite, addTargetPrefix + "/" + index);
    }

    @Override
    public void addField(
        int index, Integer offset, CompositeFieldMutations.Replacement field) {
      if (offset == null) {
        append(field.dataType(), field.length(), field.name(), field.comment(), index);
      } else {
        insertAtOffset(
            offset, field.dataType(), field.length(), field.name(), field.comment(), index);
      }
    }

    private void append(DataType dataType, int length, String name, String comment, int index) {
      String target = addTargetPrefix + "/" + index;
      int checkLength =
          composite.isPackingEnabled()
              ? length
              : effectiveComponentLength(composite, dataType, length);
      validateEndOffset(currentByteLength(composite), checkLength, target);
      composite.add(dataType, length, name, comment);
      if (composite.isPackingEnabled()
          && currentByteLength(composite) > DataTypeService.MAX_STRUCT_SIZE) {
        composite.delete(composite.getNumComponents() - 1);
        throw new DataTypeMutationValidationException(
            target, "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE);
      }
    }

    private void insertAtOffset(
        int offset, DataType dataType, int length, String name, String comment, int index) {
      String target = addTargetPrefix + "/" + index + "/offset";
      if (offset < 0) {
        throw new DataTypeMutationValidationException(
            target, "struct field offset must not be negative");
      }
      if (composite.isPackingEnabled()) {
        validateEndOffset(offset, length, target);
        validateEndOffset(Math.max(offset, currentByteLength(composite)), length, target);
        composite.insertAtOffset(offset, dataType, length, name, comment);
        if (currentByteLength(composite) > DataTypeService.MAX_STRUCT_SIZE) {
          throw new DataTypeMutationValidationException(
              target, "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE);
        }
        return;
      }
      int effectiveLength = effectiveComponentLength(composite, dataType, length);
      validateEndOffset(offset, effectiveLength, target);
      ensureUnpackedRangeAvailable(composite, offset, effectiveLength, -1, target);
      if (effectiveLength == 0 && offset == currentByteLength(composite)) {
        composite.insertAtOffset(offset, dataType, 0, name, comment);
        return;
      }
      ensureUnpackedCapacity(composite, offset, Math.max(effectiveLength, 1), target);
      composite.replaceAtOffset(offset, dataType, effectiveLength, name, comment);
    }

    @Override
    public void replace(
        DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {
      if (component.isUndefined()) {
        ensureDefinedComponentCapacity(composite, PATCH_UPDATE_FIELDS_TARGET);
      }
      int ordinal = component.getOrdinal();
      int offset = component.getOffset();
      int length = replacement.length();
      if (composite.isPackingEnabled()) {
        validateEndOffset(offset, length, PATCH_UPDATE_FIELDS_TARGET);
        composite.replace(
            ordinal,
            replacement.dataType(),
            length,
            replacement.name(),
            replacement.comment());
        if (currentByteLength(composite) > DataTypeService.MAX_STRUCT_SIZE) {
          throw new DataTypeMutationValidationException(
              PATCH_UPDATE_FIELDS_TARGET,
              "struct size must not exceed " + DataTypeService.MAX_STRUCT_SIZE);
        }
        return;
      }
      length = effectiveComponentLength(composite, replacement.dataType(), replacement.length());
      validateEndOffset(offset, length, PATCH_UPDATE_FIELDS_TARGET);
      ensureUnpackedRangeAvailable(composite, offset, length, ordinal, PATCH_UPDATE_FIELDS_TARGET);
      ensureUnpackedCapacity(
          composite, offset, Math.max(length, 1), PATCH_UPDATE_FIELDS_TARGET);
      composite.replace(
          ordinal,
          replacement.dataType(),
          length,
          replacement.name(),
          replacement.comment());
    }
  }
}
