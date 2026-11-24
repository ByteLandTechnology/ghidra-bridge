package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
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
      if (ordinal >= 0 && ordinal < composite.getNumComponents()) composite.delete(ordinal);
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
    for (DataTypePatch.CompositeField field : fields) {
      access.validateAddOffset(field.offset());
      String name = field.name() == null ? "field" : field.name();
      DataType dataType = DataTypeMutationSupport.resolveFieldDataType(field.dataType(), resolver);
      int length = DataTypeMutationSupport.fieldLength(dataType, field.length(), null);
      if (field.offset() == null) {
        access.composite().add(dataType, length, name, null);
      } else {
        access.insertAtOffset(field.offset(), dataType, length, name);
      }
    }
  }

  static List<Integer> findOrdinalsByName(Composite composite, String name) {
    List<Integer> matches = new ArrayList<>();
    for (int index = 0; index < composite.getNumComponents(); index++) {
      DataTypeComponent component = composite.getComponent(index);
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
      if (mode.replacesComponent(update)) {
        replaceComponent(access, component, update, newName, resolver);
      } else if (update.newName() != null) {
        DataTypeMutationSupport.applyMetadataPatch(component, newName, component.getComment());
      }
    }
  }

  private static void replaceComponent(
      CompositeAccess access,
      DataTypeComponent component,
      DataTypePatch.CompositeField update,
      String newName,
      Function<DataTypeReference, DataType> resolver) {
    DataType replacement =
        update.dataType() == null
            ? component.getDataType()
            : DataTypeMutationSupport.requireDataType(resolver, update.dataType());
    int length =
        DataTypeMutationSupport.fieldLength(
            replacement, update.length(), update.dataType() == null ? component.getLength() : null);
    access.replace(
        component, new Replacement(replacement, length, newName, component.getComment()));
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

    default void validateAddOffset(Integer offset) {}

    default void insertAtOffset(int offset, DataType dataType, int length, String name) {
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
