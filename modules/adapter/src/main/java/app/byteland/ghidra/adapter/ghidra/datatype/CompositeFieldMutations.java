package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.Function;

final class CompositeFieldMutations {
  private static final int SINGLE_MATCH_COUNT = 1;

  private CompositeFieldMutations() {}

  static void renameFields(
      CompositeAccess composite,
      List<DataTypePatch.CompositeField> updates,
      Function<DataTypeReference, DataType> resolver) {
    patch(composite, updates, PatchMode.RENAME, "/patch/rename_fields", resolver);
  }

  static void updateFields(
      CompositeAccess composite,
      List<DataTypePatch.CompositeField> updates,
      Function<DataTypeReference, DataType> resolver) {
    patch(composite, updates, PatchMode.UPDATE, "/patch/update_fields", resolver);
  }

  private static void patch(
      CompositeAccess composite,
      List<DataTypePatch.CompositeField> updates,
      PatchMode mode,
      String targetPrefix,
      Function<DataTypeReference, DataType> resolver) {
    if (updates == null) return;
    for (int index = 0; index < updates.size(); index++) {
      DataTypePatch.CompositeField update = updates.get(index);
      String itemTarget = targetPrefix + "/" + index;
      DataTypeComponent component = resolveSingle(composite, update, itemTarget);
      String newName = update.newName() == null ? component.getFieldName() : update.newName();
      if (mode.replacesComponent(update)) {
        replaceComponent(composite, component, update, newName, itemTarget, resolver);
      } else if (update.newName() != null) {
        DataTypeMutationSupport.applyMetadataPatch(
            component, newName, component.getComment(), itemTarget + "/new_name");
      }
    }
  }

  private static void replaceComponent(
      CompositeAccess composite,
      DataTypeComponent component,
      DataTypePatch.CompositeField update,
      String newName,
      String itemTarget,
      Function<DataTypeReference, DataType> resolver) {
    DataType replacement =
        update.dataType() == null
            ? component.getDataType()
            : DataTypeMutationSupport.requireDataType(
                resolver, update.dataType(), itemTarget + "/data_type");
    int length =
        DataTypeMutationSupport.fieldLength(
            replacement,
            update.length(),
            update.dataType() == null ? component.getLength() : null,
            itemTarget);
    composite.replace(
        component, new Replacement(replacement, length, newName, component.getComment()));
  }

  private static DataTypeComponent resolveSingle(
      CompositeAccess composite, DataTypePatch.CompositeField selector, String itemTarget) {
    List<Integer> ordinals = composite.locate(selector, itemTarget);
    String kind = composite.kind().displayName();
    if (ordinals.isEmpty()) throw new NoSuchElementException(kind + " field not found");
    if (ordinals.size() > SINGLE_MATCH_COUNT) {
      throw new DataTypeMutationValidationException(
          itemTarget + "/name", "multiple " + kind + " fields matched name: " + selector.name());
    }
    int ordinal = ordinals.getFirst();
    if (ordinal < 0 || ordinal >= composite.componentCount()) {
      throw new NoSuchElementException(kind + " field ordinal out of range: " + ordinal);
    }
    return composite.component(ordinal);
  }

  interface CompositeAccess {
    CompositeKind kind();

    List<Integer> locate(DataTypePatch.CompositeField selector, String itemTarget);

    int componentCount();

    DataTypeComponent component(int ordinal);

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
