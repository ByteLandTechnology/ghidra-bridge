package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Undefined;
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
    patch(composite, updates, PatchMode.RENAME, resolver);
  }

  static void updateFields(
      CompositeAccess composite,
      List<DataTypePatch.CompositeField> updates,
      Function<DataTypeReference, DataType> resolver) {
    patch(composite, updates, PatchMode.UPDATE, resolver);
  }

  private static void patch(
      CompositeAccess composite,
      List<DataTypePatch.CompositeField> updates,
      PatchMode mode,
      Function<DataTypeReference, DataType> resolver) {
    if (updates == null) return;
    for (DataTypePatch.CompositeField update : updates) {
      DataTypeComponent component = resolveSingle(composite, update);
      String newName = update.newName() == null ? component.getFieldName() : update.newName();
      boolean undefinedMetadataEdit =
          component.isUndefined() && (update.newName() != null || update.commentPresent());
      if (mode.replacesComponent(update) || undefinedMetadataEdit) {
        replaceComponent(composite, component, update, newName, resolver);
      } else if (update.newName() != null || update.commentPresent()) {
        DataTypeMutationSupport.applyMetadataPatch(
            component, newName, update.comment(), update.commentPresent());
      }
    }
  }

  private static void replaceComponent(
      CompositeAccess composite,
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
    composite.replace(component, new Replacement(replacement, length, newName, comment));
  }

  private static DataTypeComponent resolveSingle(
      CompositeAccess composite, DataTypePatch.CompositeField selector) {
    List<Integer> ordinals = composite.locate(selector);
    String kind = composite.kind().displayName();
    if (ordinals.isEmpty()) throw new NoSuchElementException(kind + " field not found");
    if (ordinals.size() > SINGLE_MATCH_COUNT) {
      throw new IllegalArgumentException(
          "multiple " + kind + " fields matched name: " + selector.name());
    }
    int ordinal = ordinals.getFirst();
    if (ordinal < 0 || ordinal >= composite.componentCount()) {
      throw new NoSuchElementException(kind + " field ordinal out of range: " + ordinal);
    }
    return composite.component(ordinal);
  }

  interface CompositeAccess {
    CompositeKind kind();

    List<Integer> locate(DataTypePatch.CompositeField selector);

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
