package app.byteland.ghidra.service.datatype;

import java.util.List;

/** Sealed patch specification for struct, union, and enum data types. */
public sealed interface DataTypePatch
    permits DataTypePatch.Struct, DataTypePatch.Union, DataTypePatch.EnumPatch {
  /**
   * Returns the wire kind identifier for this patch variant.
   *
   * @return patch kind identifier
   */
  default String kind() {
    return switch (this) {
      case Struct ignored -> "struct";
      case Union ignored -> "union";
      case EnumPatch ignored -> "enum";
    };
  }

  /**
   * Field descriptor used in struct and union patch operations.
   *
   * @param name target field name
   * @param newName updated field name for rename operations
   * @param offset byte offset for struct field placement
   * @param length explicit field byte length, if required
   * @param dataType field data type reference
   */
  record CompositeField(
      String name, String newName, Integer offset, Integer length, DataTypeReference dataType) {}

  /**
   * Enum member descriptor used in enum patch operations.
   *
   * @param name target enum member name
   * @param newName updated enum member name for rename operations
   * @param value integer constant value
   */
  record EnumValue(String name, String newName, Long value) {}

  /**
   * Patch operations for a struct data type.
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
    /** Defensively copies non-null field operation lists. */
    public Struct {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }

    /**
     * Returns fields to add, or {@code null}.
     *
     * @return added field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> addFields() {
      return immutableCopyOrNull(addFields);
    }

    /**
     * Returns fields to rename, or {@code null}.
     *
     * @return renamed field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> renameFields() {
      return immutableCopyOrNull(renameFields);
    }

    /**
     * Returns fields to retype or resize, or {@code null}.
     *
     * @return updated field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> updateFields() {
      return immutableCopyOrNull(updateFields);
    }

    /**
     * Returns fields to remove, or {@code null}.
     *
     * @return removed field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> removeFields() {
      return immutableCopyOrNull(removeFields);
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
    /** Defensively copies non-null field operation lists. */
    public Union {
      addFields = immutableCopyOrNull(addFields);
      renameFields = immutableCopyOrNull(renameFields);
      updateFields = immutableCopyOrNull(updateFields);
      removeFields = immutableCopyOrNull(removeFields);
    }

    /**
     * Returns fields to add, or {@code null}.
     *
     * @return added field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> addFields() {
      return immutableCopyOrNull(addFields);
    }

    /**
     * Returns fields to rename, or {@code null}.
     *
     * @return renamed field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> renameFields() {
      return immutableCopyOrNull(renameFields);
    }

    /**
     * Returns fields to retype or resize, or {@code null}.
     *
     * @return updated field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> updateFields() {
      return immutableCopyOrNull(updateFields);
    }

    /**
     * Returns fields to remove, or {@code null}.
     *
     * @return removed field descriptors, or {@code null}
     */
    @Override
    public List<CompositeField> removeFields() {
      return immutableCopyOrNull(removeFields);
    }
  }

  /**
   * Patch operations for an enum data type.
   *
   * @param addValues enum members to add
   * @param removeValues enum members to remove
   * @param renameValues enum members to rename
   * @param updateValues enum members whose values are updated
   */
  record EnumPatch(
      List<EnumValue> addValues,
      List<EnumValue> removeValues,
      List<EnumValue> renameValues,
      List<EnumValue> updateValues)
      implements DataTypePatch {
    /** Defensively copies non-null enum operation lists. */
    public EnumPatch {
      addValues = immutableCopyOrNull(addValues);
      removeValues = immutableCopyOrNull(removeValues);
      renameValues = immutableCopyOrNull(renameValues);
      updateValues = immutableCopyOrNull(updateValues);
    }

    /**
     * Returns enum members to add, or {@code null}.
     *
     * @return added enum member descriptors, or {@code null}
     */
    @Override
    public List<EnumValue> addValues() {
      return immutableCopyOrNull(addValues);
    }

    /**
     * Returns enum members to remove, or {@code null}.
     *
     * @return removed enum member descriptors, or {@code null}
     */
    @Override
    public List<EnumValue> removeValues() {
      return immutableCopyOrNull(removeValues);
    }

    /**
     * Returns enum members to rename, or {@code null}.
     *
     * @return renamed enum member descriptors, or {@code null}
     */
    @Override
    public List<EnumValue> renameValues() {
      return immutableCopyOrNull(renameValues);
    }

    /**
     * Returns enum members whose values are updated, or {@code null}.
     *
     * @return updated enum member descriptors, or {@code null}
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
