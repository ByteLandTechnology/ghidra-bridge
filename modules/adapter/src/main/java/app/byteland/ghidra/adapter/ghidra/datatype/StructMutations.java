package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import java.util.List;
import java.util.function.Function;

final class StructMutations {
  private StructMutations() {}

  static void edit(
      Structure structure,
      DataTypePatch.Struct patch,
      Function<DataTypeReference, DataType> resolver) {
    CompositeFieldMutations.edit(
        new StructureAccess(structure),
        patch.removeFields(),
        patch.renameFields(),
        patch.updateFields(),
        patch.addFields(),
        resolver);
  }

  private record StructureAccess(Structure composite)
      implements CompositeFieldMutations.CompositeAccess {
    @Override
    public CompositeFieldMutations.CompositeKind kind() {
      return CompositeFieldMutations.CompositeKind.STRUCT;
    }

    @Override
    public List<Integer> locate(DataTypePatch.CompositeField selector) {
      if (selector.offset() != null) {
        DataTypeComponent component =
            composite.getDefinedComponentAtOrAfterOffset(selector.offset());
        return component != null && component.getOffset() == selector.offset()
            ? List.of(component.getOrdinal())
            : List.of();
      }
      if (selector.name() == null) {
        throw new IllegalArgumentException("struct field selector requires name or offset");
      }
      return CompositeFieldMutations.findOrdinalsByName(composite, selector.name());
    }

    @Override
    public void insertAtOffset(int offset, DataType dataType, int length, String name) {
      composite.insertAtOffset(offset, dataType, length, name, null);
    }

    @Override
    public void replace(
        DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {
      composite.replace(
          component.getOrdinal(),
          replacement.dataType(),
          replacement.length(),
          replacement.name(),
          replacement.comment());
    }
  }
}
