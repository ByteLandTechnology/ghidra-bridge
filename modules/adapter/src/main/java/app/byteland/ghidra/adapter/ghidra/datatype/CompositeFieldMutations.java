package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Undefined;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Function;

final class CompositeFieldMutations {
  private static final int SINGLE_MATCH_COUNT = 1;

  private CompositeFieldMutations() {}

  static void edit(
      CompositeAccess access,
      List<DataTypePatch.CompositeField> removeFields,
      List<DataTypePatch.CompositeField> renameFields,
      List<DataTypePatch.CompositeField> updateFields,
      List<DataTypePatch.CompositeField> addFields,
      Function<DataTypeReference, DataType> resolver) {
    removeFields(access, removeFields);
    renameFields(access, renameFields, resolver);
    updateFields(access, updateFields, resolver);
    addFields(access, addFields, resolver);
  }

  static void removeFields(
      CompositeAccess access, List<DataTypePatch.CompositeField> selectors) {
    if (selectors == null) return;
    List<Integer> ordinals = new ArrayList<>();
    for (DataTypePatch.CompositeField selector : selectors) {
      ordinals.addAll(access.locate(selector));
    }
    Composite composite = access.composite();
    ordinals = ordinals.stream().distinct().sorted(Collections.reverseOrder()).toList();
    for (int ordinal : ordinals) {
      if (ordinal >= 0 && ordinal < composite.getNumComponents()) {
        access.removeComponent(ordinal);
      }
    }
  }

  static void renameFields(
      CompositeAccess access,
      List<DataTypePatch.CompositeField> updates,
      Function<DataTypeReference, DataType> resolver) {
    patch(access, updates, PatchMode.RENAME, resolver);
  }

  static void updateFields(
      CompositeAccess access,
      List<DataTypePatch.CompositeField> updates,
      Function<DataTypeReference, DataType> resolver) {
    patch(access, updates, PatchMode.UPDATE, resolver);
  }

  static void addFields(
      CompositeAccess access,
      List<DataTypePatch.CompositeField> fields,
      Function<DataTypeReference, DataType> resolver) {
    if (fields == null) return;
    for (int index = 0; index < fields.size(); index++) {
      DataTypePatch.CompositeField field = fields.get(index);
      access.validateBeforeAdd(field, index);
      String name = field.name() == null ? "field" : field.name();
      DataType dataType = DataTypeMutationSupport.resolveFieldDataType(field.dataType(), resolver);
      int length = DataTypeMutationSupport.fieldLength(dataType, field.length(), null);
      String comment = DataTypeMutationSupport.normalizeComment(field.comment());
      if (field.offset() == null) {
        access.append(dataType, length, name, comment, index);
      } else {
        access.insertAtOffset(field.offset(), dataType, length, name, comment, index);
      }
    }
  }

  static List<Integer> findOrdinalsByName(Composite composite, String name) {
    List<Integer> matches = new ArrayList<>();
    for (DataTypeComponent component : composite.getDefinedComponents()) {
      if (name.equals(component.getFieldName())) matches.add(component.getOrdinal());
    }
    return matches;
  }

  private static void patch(
      CompositeAccess access,
      List<DataTypePatch.CompositeField> updates,
      PatchMode mode,
      Function<DataTypeReference, DataType> resolver) {
    if (updates == null) return;
    for (DataTypePatch.CompositeField update : updates) {
      DataTypeComponent component = resolveSingle(access, update);
      String newName = update.newName() == null ? component.getFieldName() : update.newName();
      boolean undefinedMetadataEdit =
          component.isUndefined() && (update.newName() != null || update.commentPresent());
      if (mode.replacesComponent(update) || undefinedMetadataEdit) {
        replaceComponent(access, component, update, newName, resolver);
      } else if (update.newName() != null || update.commentPresent()) {
        DataTypeMutationSupport.applyMetadataPatch(
            component, newName, update.comment(), update.commentPresent());
      }
    }
  }

  private static void replaceComponent(
      CompositeAccess access,
      DataTypeComponent component,
      DataTypePatch.CompositeField update,
      String newName,
      Function<DataTypeReference, DataType> resolver) {
    int fallbackLength = component.getLength() > 0 ? component.getLength() : 1;
    DataType replacement;
    int length;
    if (update.dataType() != null) {
      replacement = DataTypeMutationSupport.requireDataType(resolver, update.dataType());
      length = DataTypeMutationSupport.fieldLength(replacement, update.length(), null);
    } else if (component.isUndefined()) {
      int requestedLength =
          update.length() != null
              ? DataTypeMutationSupport.fieldLength(
                  Undefined.getUndefinedDataType(1), update.length(), null)
              : fallbackLength;
      replacement = Undefined.getUndefinedDataType(requestedLength);
      length = requestedLength;
    } else {
      replacement = component.getDataType();
      length = DataTypeMutationSupport.fieldLength(replacement, update.length(), fallbackLength);
    }
    String comment =
        update.commentPresent()
            ? DataTypeMutationSupport.normalizeComment(update.comment())
            : component.getComment();
    access.replace(component, new Replacement(replacement, length, newName, comment));
  }

  private static DataTypeComponent resolveSingle(
      CompositeAccess access, DataTypePatch.CompositeField selector) {
    List<Integer> ordinals = access.locate(selector);
    String kind = access.kind().displayName();
    if (ordinals.isEmpty()) throw new NoSuchElementException(kind + " field not found");
    if (ordinals.size() > SINGLE_MATCH_COUNT) {
      throw new IllegalArgumentException(
          "multiple " + kind + " fields matched name: " + selector.name());
    }
    int ordinal = ordinals.getFirst();
    Composite composite = access.composite();
    if (ordinal < 0 || ordinal >= composite.getNumComponents()) {
      throw new NoSuchElementException(kind + " field ordinal out of range: " + ordinal);
    }
    return composite.getComponent(ordinal);
  }

  interface CompositeAccess {
    CompositeKind kind();

    Composite composite();

    List<Integer> locate(DataTypePatch.CompositeField selector);

    default void removeComponent(int ordinal) {
      composite().delete(ordinal);
    }

    default void validateAddOffset(Integer offset) {}

    default void validateBeforeAdd(DataTypePatch.CompositeField field, int index) {
      validateAddOffset(field.offset());
    }

    default void append(DataType dataType, int length, String name, String comment, int index) {
      composite().add(dataType, length, name, comment);
    }

    default void insertAtOffset(
        int offset, DataType dataType, int length, String name, String comment, int index) {
      throw new IllegalArgumentException(
          kind().displayName() + " add_fields does not support offset");
    }

    void replace(DataTypeComponent component, Replacement replacement);
  }

  enum CompositeKind {
    STRUCT("struct"),
    UNION("union");

    private final String label;

    CompositeKind(String label) {
      this.label = label;
    }

    String displayName() {
      return label;
    }
  }

  record Replacement(DataType dataType, int length, String name, String comment) {}

  private enum PatchMode {
    RENAME {
      @Override
      boolean replacesComponent(DataTypePatch.CompositeField update) {
        return false;
      }
    },
    UPDATE {
      @Override
      boolean replacesComponent(DataTypePatch.CompositeField update) {
        return update.dataType() != null || update.length() != null;
      }
    };

    abstract boolean replacesComponent(DataTypePatch.CompositeField update);
  }
}
