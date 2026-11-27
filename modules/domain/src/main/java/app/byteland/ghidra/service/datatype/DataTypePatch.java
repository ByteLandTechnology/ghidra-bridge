package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Typed mutation patch for structure, union, and enumeration data types.
 */
public sealed interface DataTypePatch
    permits DataTypePatch.Struct, DataTypePatch.Union, DataTypePatch.EnumPatch {
  /**
   * Returns the lowercase wire kind name of this patch variant.
   *
   * @return {@code "struct"}, {@code "union"}, or {@code "enum"}
   */
  default String kind() {
    return switch (this) {
      case Struct ignored -> "struct";
      case Union ignored -> "union";
      case EnumPatch ignored -> "enum";
    };
  }

  /**
   * Field specification for structure and union patch operations.
   *
   * @param name target or added field name
   * @param newName replacement field name for rename operations
   * @param offset optional byte offset inside a structure
   * @param length optional explicit byte length
   * @param dataType optional field data type reference
   */
  record CompositeField(
      String name, String newName, Integer offset, Integer length, DataTypeReference dataType) {}

  /**
   * Member specification for enumeration patch operations.
   *
   * @param name target or added member name
   * @param newName replacement member name for rename operations
   * @param value optional integer constant value
   */
  record EnumValue(String name, String newName, Long value) {}

  /**
   * Patch operations for a structure data type.
   *
   * @param addFields fields to add
   * @param renameFields fields to rename
   * @param updateFields fields to retype or resize
   * @param removeFields fields to remove
   */
  record Struct(
      List<CompositeField> addFields,
      List<CompositeField> renameFields,
      List<CompositeField> updateFields,
      List<CompositeField> removeFields)
      implements DataTypePatch {
    /** Copies non-null field lists into immutable lists. */
    public Struct {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }
  }

  /**
   * Patch operations for a union data type.
   *
   * @param addFields fields to add
   * @param renameFields fields to rename
   * @param updateFields fields to retype or resize
   * @param removeFields fields to remove
   */
  record Union(
      List<CompositeField> addFields,
      List<CompositeField> renameFields,
      List<CompositeField> updateFields,
      List<CompositeField> removeFields)
      implements DataTypePatch {
    /** Copies non-null field lists into immutable lists. */
    public Union {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }
  }

  /**
   * Patch operations for an enumeration data type.
   *
   * @param addValues members to add
   * @param removeValues members to remove
   * @param renameValues members to rename
   * @param updateValues members whose numeric values change
   */
  record EnumPatch(
      List<EnumValue> addValues,
      List<EnumValue> removeValues,
      List<EnumValue> renameValues,
      List<EnumValue> updateValues)
      implements DataTypePatch {
    /** Copies non-null member lists into immutable lists. */
    public EnumPatch {
      addValues = immutableCopyOrNull(addValues);
      removeValues = immutableCopyOrNull(removeValues);
      renameValues = immutableCopyOrNull(renameValues);
      updateValues = immutableCopyOrNull(updateValues);
    }
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }
}
