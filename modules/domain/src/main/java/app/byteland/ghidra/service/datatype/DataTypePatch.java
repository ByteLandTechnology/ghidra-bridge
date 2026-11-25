package app.byteland.ghidra.service.datatype;

import java.util.List;

public sealed interface DataTypePatch
    permits DataTypePatch.Struct,
        DataTypePatch.Union,
        DataTypePatch.EnumPatch,
        DataTypePatch.Typedef {
  default String kind() {
    return switch (this) {
      case Struct ignored -> "struct";
      case Union ignored -> "union";
      case EnumPatch ignored -> "enum";
      case Typedef ignored -> "typedef";
    };
  }

  record CompositeField(
      String name,
      String newName,
      Integer offset,
      Integer length,
      DataTypeReference dataType,
      String comment,
      boolean hasComment) {
    public CompositeField(
        String name, String newName, Integer offset, Integer length, DataTypeReference dataType) {
      this(name, newName, offset, length, dataType, null, false);
    }

    public CompositeField(
        String name,
        String newName,
        Integer offset,
        Integer length,
        DataTypeReference dataType,
        String comment) {
      this(name, newName, offset, length, dataType, comment, comment != null);
    }
  }

  record EnumValue(String name, String newName, Long value, String comment, boolean hasComment) {
    public EnumValue(String name, String newName, Long value) {
      this(name, newName, value, null, false);
    }

    public EnumValue(String name, String newName, Long value, String comment) {
      this(name, newName, value, comment, comment != null);
    }
  }

  record Struct(
      List<CompositeField> addFields,
      List<CompositeField> renameFields,
      List<CompositeField> updateFields,
      List<CompositeField> removeFields,
      boolean preserveOffsets)
      implements DataTypePatch {
    public Struct(
        List<CompositeField> addFields,
        List<CompositeField> renameFields,
        List<CompositeField> updateFields,
        List<CompositeField> removeFields) {
      this(addFields, renameFields, updateFields, removeFields, true);
    }

    public Struct {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }
  }

  record Union(
      List<CompositeField> addFields,
      List<CompositeField> renameFields,
      List<CompositeField> updateFields,
      List<CompositeField> removeFields)
      implements DataTypePatch {
    public Union {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }
  }

  record EnumPatch(
      List<EnumValue> addValues,
      List<EnumValue> removeValues,
      List<EnumValue> renameValues,
      List<EnumValue> updateValues)
      implements DataTypePatch {
    public EnumPatch {
      addValues = immutableCopyOrNull(addValues);
      removeValues = immutableCopyOrNull(removeValues);
      renameValues = immutableCopyOrNull(renameValues);
      updateValues = immutableCopyOrNull(updateValues);
    }
  }

  record Typedef(DataTypeReference baseType) implements DataTypePatch {}

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }
}
