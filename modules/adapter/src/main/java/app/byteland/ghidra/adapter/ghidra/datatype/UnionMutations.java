package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

final class UnionMutations {
  private UnionMutations() {}

  static void edit(
      Union union, DataTypePatch.Union patch, Function<DataTypeReference, DataType> resolver) {
    UnionAccess access = new UnionAccess(union);
    remove(union, patch.removeFields());
    CompositeFieldMutations.renameFields(access, patch.renameFields(), resolver);
    CompositeFieldMutations.updateFields(access, patch.updateFields(), resolver);
    if (patch.addFields() != null) {
      for (int index = 0; index < patch.addFields().size(); index++) {
        DataTypePatch.CompositeField field = patch.addFields().get(index);
        String itemTarget = "/patch/add_fields/" + index;
        if (field.offset() != null) {
          throw new DataTypeMutationValidationException(
              itemTarget + "/offset", "union add_fields does not support offset");
        }
        DataType dataType =
            DataTypeMutationSupport.resolveFieldDataType(
                field.dataType(), resolver, itemTarget + "/data_type");
        union.add(
            dataType,
            DataTypeMutationSupport.fieldLength(dataType, field.length(), null, itemTarget),
            field.name() == null ? "field" : field.name(),
            null);
      }
    }
  }

  private static void remove(Union union, List<DataTypePatch.CompositeField> selectors) {
    if (selectors == null) return;
    List<Integer> ordinals = new ArrayList<>();
    for (int index = 0; index < selectors.size(); index++) {
      ordinals.addAll(
          resolveOrdinals(union, selectors.get(index), "/patch/remove_fields/" + index));
    }
    ordinals = ordinals.stream().distinct().sorted(Collections.reverseOrder()).toList();
    for (int ordinal : ordinals) {
      if (ordinal >= 0 && ordinal < union.getNumComponents()) union.delete(ordinal);
    }
  }

  private static List<Integer> resolveOrdinals(
      Union union, DataTypePatch.CompositeField selector, String itemTarget) {
    if (selector.offset() != null) {
      throw new DataTypeMutationValidationException(
          itemTarget + "/offset", "union field selector requires name");
    }
    if (selector.name() == null) {
      throw new DataTypeMutationValidationException(
          itemTarget + "/name", "union field selector requires name");
    }
    List<Integer> matches = new ArrayList<>();
    for (int index = 0; index < union.getNumComponents(); index++) {
      DataTypeComponent component = union.getComponent(index);
      if (selector.name().equals(component.getFieldName())) matches.add(component.getOrdinal());
    }
    return matches;
  }

  private record UnionAccess(Union union) implements CompositeFieldMutations.CompositeAccess {
    @Override
    public CompositeFieldMutations.CompositeKind kind() {
      return CompositeFieldMutations.CompositeKind.UNION;
    }

    @Override
    public List<Integer> locate(DataTypePatch.CompositeField selector, String itemTarget) {
      return resolveOrdinals(union, selector, itemTarget);
    }

    @Override
    public int componentCount() {
      return union.getNumComponents();
    }

    @Override
    public DataTypeComponent component(int ordinal) {
      return union.getComponent(ordinal);
    }

    @Override
    public void replace(
        DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {
      int ordinal = component.getOrdinal();
      union.delete(ordinal);
      union.insert(
          ordinal,
          replacement.dataType(),
          replacement.length(),
          replacement.name(),
          replacement.comment());
    }
  }
}
