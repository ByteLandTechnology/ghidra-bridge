package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Represents incremental mutations for structure, union, or enumeration data types.
 */
public sealed interface DataTypePatch
    permits DataTypePatch.Struct, DataTypePatch.Union, DataTypePatch.EnumPatch {
  /**
   * Returns the wire kind identifier for this patch variant.
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
   * Describes a structure or union field mutation item.
   *
   * @param name target field name
   * @param newName replacement field name for renames
   * @param offset optional byte offset inside a structure
   * @param length optional explicit field length in bytes
   * @param dataType optional field data type reference
   */
  record CompositeField(
      String name, String newName, Integer offset, Integer length, DataTypeReference dataType) {}

  /**
   * Describes an enumeration constant mutation item.
   *
   * @param name target enumeration constant name
   * @param newName replacement constant name for renames
   * @param value optional numeric constant value
   */
  record EnumValue(String name, String newName, Long value) {}

  /**
   * Incremental field operations for a structure data type.
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
    /** Copies field operation lists into immutable lists when present. */
    public Struct {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }

    /**
     * Returns an immutable copy of fields to add, or null when absent.
     *
     * @return fields to add or null
     */
    @Override
    public List<CompositeField> addFields() {
      return immutableCopyOrNull(addFields);
    }

    /**
     * Returns an immutable copy of fields to rename, or null when absent.
     *
     * @return fields to rename or null
     */
    @Override
    public List<CompositeField> renameFields() {
      return immutableCopyOrNull(renameFields);
    }

    /**
     * Returns an immutable copy of fields to update, or null when absent.
     *
     * @return fields to update or null
     */
    @Override
    public List<CompositeField> updateFields() {
      return immutableCopyOrNull(updateFields);
    }

    /**
     * Returns an immutable copy of fields to remove, or null when absent.
     *
     * @return fields to remove or null
     */
    @Override
    public List<CompositeField> removeFields() {
      return immutableCopyOrNull(removeFields);
    }
  }

  /**
   * Incremental field operations for a union data type.
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
    /** Copies field operation lists into immutable lists when present. */
    public Union {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }

    /**
     * Returns an immutable copy of fields to add, or null when absent.
     *
     * @return fields to add or null
     */
    @Override
    public List<CompositeField> addFields() {
      return immutableCopyOrNull(addFields);
    }

    /**
     * Returns an immutable copy of fields to rename, or null when absent.
     *
     * @return fields to rename or null
     */
    @Override
    public List<CompositeField> renameFields() {
      return immutableCopyOrNull(renameFields);
    }

    /**
     * Returns an immutable copy of fields to update, or null when absent.
     *
     * @return fields to update or null
     */
    @Override
    public List<CompositeField> updateFields() {
      return immutableCopyOrNull(updateFields);
    }

    /**
     * Returns an immutable copy of fields to remove, or null when absent.
     *
     * @return fields to remove or null
     */
    @Override
    public List<CompositeField> removeFields() {
      return immutableCopyOrNull(removeFields);
    }
  }

  /**
   * Incremental member operations for an enumeration data type.
   *
   * @param addValues constants to add
   * @param removeValues constants to remove
   * @param renameValues constants to rename
   * @param updateValues constants whose values change
   */
  record EnumPatch(
      List<EnumValue> addValues,
      List<EnumValue> removeValues,
      List<EnumValue> renameValues,
      List<EnumValue> updateValues)
      implements DataTypePatch {
    /** Copies member operation lists into immutable lists when present. */
    public EnumPatch {
      addValues = immutableCopyOrNull(addValues);
      removeValues = immutableCopyOrNull(removeValues);
      renameValues = immutableCopyOrNull(renameValues);
      updateValues = immutableCopyOrNull(updateValues);
    }

    /**
     * Returns an immutable copy of constants to add, or null when absent.
     *
     * @return constants to add or null
     */
    @Override
    public List<EnumValue> addValues() {
      return immutableCopyOrNull(addValues);
    }

    /**
     * Returns an immutable copy of constants to remove, or null when absent.
     *
     * @return constants to remove or null
     */
    @Override
    public List<EnumValue> removeValues() {
      return immutableCopyOrNull(removeValues);
    }

    /**
     * Returns an immutable copy of constants to rename, or null when absent.
     *
     * @return constants to rename or null
     */
    @Override
    public List<EnumValue> renameValues() {
      return immutableCopyOrNull(renameValues);
    }

    /**
     * Returns an immutable copy of constants to update, or null when absent.
     *
     * @return constants to update or null
     */
    @Override
    public List<EnumValue> updateValues() {
      return immutableCopyOrNull(updateValues);
    }
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }
}
