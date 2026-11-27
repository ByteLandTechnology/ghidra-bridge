package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Union;
import java.util.List;
import java.util.function.Function;

final class UnionMutations {
  private UnionMutations() {}

  static void edit(
      Union union, DataTypePatch.Union patch, Function<DataTypeReference, DataType> resolver) {
    CompositeFieldMutations.edit(
        new UnionAccess(union),
        patch.removeFields(),
        patch.renameFields(),
        patch.updateFields(),
        patch.addFields(),
        resolver);
  }

  private record UnionAccess(Union composite) implements CompositeFieldMutations.CompositeAccess {
    @Override
    public CompositeFieldMutations.CompositeKind kind() {
      return CompositeFieldMutations.CompositeKind.UNION;
    }

    @Override
    public List<Integer> locate(DataTypePatch.CompositeField selector) {
      if (selector.offset() != null || selector.name() == null) {
        throw new IllegalArgumentException("union field selector requires name");
      }
      return CompositeFieldMutations.findOrdinalsByName(composite, selector.name());
    }

    @Override
    public void validateBeforeAdd(DataTypePatch.CompositeField field, int index) {
      if (field.offset() != null) {
        throw new IllegalArgumentException("union add_fields does not support offset");
      }
    }

    @Override
    public void replace(
        DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {
      int ordinal = component.getOrdinal();
      composite.delete(ordinal);
      composite.insert(
          ordinal,
          replacement.dataType(),
          replacement.length(),
          replacement.name(),
          replacement.comment());
    }
  }
}
