package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypePatch.CompositeField;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.util.UniversalIdGenerator;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class CompositeFieldMutationsTest {
  private static final Map<DataTypeReference, DataType> TYPES;
  private static final Function<DataTypeReference, DataType> RESOLVER;

  static {
    UniversalIdGenerator.initialize();
    TYPES =
        Map.of(
            DataTypeReference.named("byte"), ByteDataType.dataType,
            DataTypeReference.named("short"), ShortDataType.dataType,
            DataTypeReference.named("int"), IntegerDataType.dataType,
            DataTypeReference.named("fn"), new FunctionDefinitionDataType("callback"),
            DataTypeReference.arrayOf(DataTypeReference.named("byte"), 4),
                new ArrayDataType(ByteDataType.dataType, 4, 1));
    RESOLVER = TYPES::get;
  }

  @Test
  void structEditRunsRemoveRenameUpdateThenAddInOrder() {
    StructureDataType struct = new StructureDataType("Packet", 0);
    struct.add(ByteDataType.dataType, 1, "alpha", "header-comment");
    struct.add(IntegerDataType.dataType, 4, "beta", null);

    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            List.of(new CompositeField("alpha", null, null, null, DataTypeReference.named("short"))),
            List.of(new CompositeField("alpha", "beta", null, null, null)),
            List.of(new CompositeField("beta", null, null, null, DataTypeReference.named("int"))),
            List.of(new CompositeField("beta", null, null, null, null))),
        RESOLVER);

    assertEquals(2, struct.getNumComponents());
    DataTypeComponent first = struct.getComponent(0);
    assertEquals("beta", first.getFieldName());
    assertInstanceOf(IntegerDataType.class, first.getDataType());
    assertEquals(4, first.getLength());
    assertEquals("header-comment", first.getComment());

    DataTypeComponent second = struct.getComponent(1);
    assertEquals("alpha", second.getFieldName());
    assertInstanceOf(ShortDataType.class, second.getDataType());
    assertEquals(2, second.getLength());
  }

  @Test
  void unionEditRunsRemoveRenameUpdateThenAddInOrder() {
    UnionDataType union = new UnionDataType("Variant");
    union.add(ByteDataType.dataType, 1, "alpha", "variant-comment");
    union.add(IntegerDataType.dataType, 4, "beta", null);

    UnionMutations.edit(
        union,
        new DataTypePatch.Union(
            List.of(new CompositeField("alpha", null, null, null, DataTypeReference.named("short"))),
            List.of(new CompositeField("alpha", "beta", null, null, null)),
            List.of(new CompositeField("beta", null, null, null, DataTypeReference.named("int"))),
            List.of(new CompositeField("beta", null, null, null, null))),
        RESOLVER);

    assertEquals(2, union.getNumComponents());
    DataTypeComponent first = union.getComponent(0);
    assertEquals("beta", first.getFieldName());
    assertInstanceOf(IntegerDataType.class, first.getDataType());
    assertEquals(4, first.getLength());
    assertEquals("variant-comment", first.getComment());

    DataTypeComponent second = union.getComponent(1);
    assertEquals("alpha", second.getFieldName());
    assertInstanceOf(ShortDataType.class, second.getDataType());
    assertEquals(2, second.getLength());
  }

  @Test
  void removeFieldsDeletesDistinctOrdinalsInReverseOrderForStructAndUnion() {
    StructureDataType struct = new StructureDataType("Items", 0);
    struct.add(ByteDataType.dataType, 1, "f0", null);
    struct.add(ShortDataType.dataType, 2, "f1", null);
    struct.add(IntegerDataType.dataType, 4, "f2", null);
    struct.add(ByteDataType.dataType, 1, "f3", null);

    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            null,
            null,
            null,
            List.of(
                new CompositeField("f0", null, null, null, null),
                new CompositeField("f2", null, null, null, null),
                new CompositeField(null, null, 3, null, null),
                new CompositeField("missing", null, null, null, null))),
        RESOLVER);

    assertEquals(2, struct.getNumComponents());
    assertEquals("f1", struct.getComponent(0).getFieldName());
    assertEquals("f3", struct.getComponent(1).getFieldName());

    UnionDataType union = new UnionDataType("UnionItems");
    union.add(ByteDataType.dataType, 1, "u0", null);
    union.add(ShortDataType.dataType, 2, "u1", null);
    union.add(IntegerDataType.dataType, 4, "u2", null);
    union.add(ByteDataType.dataType, 1, "u3", null);

    UnionMutations.edit(
        union,
        new DataTypePatch.Union(
            null,
            null,
            null,
            List.of(
                new CompositeField("u0", null, null, null, null),
                new CompositeField("u2", null, null, null, null),
                new CompositeField("u2", null, null, null, null),
                new CompositeField("missing", null, null, null, null))),
        RESOLVER);

    assertEquals(2, union.getNumComponents());
    assertEquals("u1", union.getComponent(0).getFieldName());
    assertEquals("u3", union.getComponent(1).getFieldName());
  }

  @Test
  void findOrdinalsByNameScansAllComponentSlotsIncludingUndefinedAndDuplicates() {
    StructureDataType struct = new StructureDataType("Padded", 6);
    struct.replaceAtOffset(4, ShortDataType.dataType, 2, "tail", null);
    assertTrue(struct.getComponent(0).isUndefined());
    assertEquals(5, struct.getNumComponents());
    assertEquals(1, struct.getNumDefinedComponents());
    assertEquals(List.of(4), CompositeFieldMutations.findOrdinalsByName(struct, "tail"));

    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            null,
            List.of(new CompositeField("tail", "renamed_tail", null, null, null)),
            null,
            null),
        RESOLVER);
    assertEquals("renamed_tail", struct.getComponent(4).getFieldName());

    DataTypeComponent unnamedSlot =
        (DataTypeComponent)
            Proxy.newProxyInstance(
                DataTypeComponent.class.getClassLoader(),
                new Class<?>[] {DataTypeComponent.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getFieldName" -> null;
                      case "getOrdinal" -> 0;
                      default -> throw new AssertionError(method.getName());
                    });
    DataTypeComponent namedUndefinedSlot =
        (DataTypeComponent)
            Proxy.newProxyInstance(
                DataTypeComponent.class.getClassLoader(),
                new Class<?>[] {DataTypeComponent.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getFieldName" -> "undef_slot";
                      case "getOrdinal" -> 1;
                      default -> throw new AssertionError(method.getName());
                    });
    Composite undefinedOnlyComposite =
        (Composite)
            Proxy.newProxyInstance(
                Composite.class.getClassLoader(),
                new Class<?>[] {Composite.class},
                (proxy, method, args) -> {
                  if (method.isDefault()) {
                    return InvocationHandler.invokeDefault(proxy, method, args);
                  }
                  return switch (method.getName()) {
                    case "getNumComponents" -> 2;
                    case "getComponent" -> ((int) args[0]) == 0 ? unnamedSlot : namedUndefinedSlot;
                    case "getNumDefinedComponents" -> 0;
                    case "getDefinedComponents" -> new DataTypeComponent[0];
                    default -> throw new AssertionError(method.getName());
                  };
                });
    assertEquals(List.of(), undefinedOnlyComposite.findComponents("undef_slot"));
    assertEquals(
        List.of(1),
        CompositeFieldMutations.findOrdinalsByName(undefinedOnlyComposite, "undef_slot"));

    StructureDataType duplicateStruct = new StructureDataType("DupStruct", 0);
    duplicateStruct.add(ByteDataType.dataType, 1, "dup", null);
    duplicateStruct.add(ByteDataType.dataType, 1, "dup", null);
    var structDupError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                StructMutations.edit(
                    duplicateStruct,
                    new DataTypePatch.Struct(
                        null,
                        List.of(new CompositeField("dup", "unique", null, null, null)),
                        null,
                        null),
                    RESOLVER));
    assertEquals("multiple struct fields matched name: dup", structDupError.getMessage());

    UnionDataType duplicateUnion = new UnionDataType("DupUnion");
    duplicateUnion.add(ByteDataType.dataType, 1, "dup", null);
    duplicateUnion.add(ShortDataType.dataType, 2, "dup", null);
    var unionDupError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                UnionMutations.edit(
                    duplicateUnion,
                    new DataTypePatch.Union(
                        null,
                        null,
                        List.of(
                            new CompositeField(
                                "dup", null, null, null, DataTypeReference.named("int"))),
                        null),
                    RESOLVER));
    assertEquals("multiple union fields matched name: dup", unionDupError.getMessage());
  }

  @Test
  void defaultFieldAdditionAndResolveFieldDataTypeDelegateToRequireDataType() {
    AtomicReference<DataTypeReference> captured = new AtomicReference<>();
    Function<DataTypeReference, DataType> trackingResolver =
        reference -> {
          captured.set(reference);
          return RESOLVER.apply(reference);
        };

    StructureDataType struct = new StructureDataType("Defaults", 0);
    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            List.of(new CompositeField(null, null, null, null, null)), null, null, null),
        trackingResolver);
    assertEquals(DataTypeReference.named("byte"), captured.get());
    assertEquals(1, struct.getNumComponents());
    assertEquals("field", struct.getComponent(0).getFieldName());
    assertInstanceOf(ByteDataType.class, struct.getComponent(0).getDataType());
    assertEquals(1, struct.getComponent(0).getLength());

    UnionDataType union = new UnionDataType("UnionDefaults");
    UnionMutations.edit(
        union,
        new DataTypePatch.Union(
            List.of(new CompositeField(null, null, null, null, null)), null, null, null),
        trackingResolver);
    assertEquals(1, union.getNumComponents());
    assertEquals("field", union.getComponent(0).getFieldName());
    assertInstanceOf(ByteDataType.class, union.getComponent(0).getDataType());
    assertEquals(1, union.getComponent(0).getLength());

    var unknownDefault =
        assertThrows(
            IllegalArgumentException.class,
            () -> DataTypeMutationSupport.resolveFieldDataType(null, ignored -> null));
    assertEquals(
        "unknown data type: " + DataTypeReference.named("byte"), unknownDefault.getMessage());

    var bareFunction =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                DataTypeMutationSupport.resolveFieldDataType(
                    DataTypeReference.named("fn"), RESOLVER));
    assertEquals(
        "data_type must use kind=pointer for a function definition", bareFunction.getMessage());
  }

  @Test
  void addFieldsPreservesDistinctOffsetEvaluationOrderForUnionAndStruct() {
    UnionDataType union = new UnionDataType("OffsetUnion");
    var unionOffsetError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                UnionMutations.edit(
                    union,
                    new DataTypePatch.Union(
                        List.of(
                            new CompositeField(
                                "bad", null, 0, -1, DataTypeReference.named("missing"))),
                        null,
                        null,
                        null),
                    ignored -> {
                      throw new AssertionError("resolver must not run before union offset check");
                    }));
    assertEquals("union add_fields does not support offset", unionOffsetError.getMessage());

    StructureDataType struct = new StructureDataType("OffsetStruct", 0);
    var unknownBeforeInsert =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                StructMutations.edit(
                    struct,
                    new DataTypePatch.Struct(
                        List.of(
                            new CompositeField(
                                "bad_type", null, -1, null, DataTypeReference.named("missing"))),
                        null,
                        null,
                        null),
                    RESOLVER));
    assertEquals(
        "unknown data type: " + DataTypeReference.named("missing"),
        unknownBeforeInsert.getMessage());

    var lengthBeforeInsert =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                StructMutations.edit(
                    struct,
                    new DataTypePatch.Struct(
                        List.of(
                            new CompositeField(
                                "bad_len", null, -1, 0, DataTypeReference.named("int"))),
                        null,
                        null,
                        null),
                    RESOLVER));
    assertEquals("length must be positive", lengthBeforeInsert.getMessage());

    var arrayLengthBeforeInsert =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                StructMutations.edit(
                    struct,
                    new DataTypePatch.Struct(
                        List.of(
                            new CompositeField(
                                "bad_arr",
                                null,
                                -1,
                                4,
                                DataTypeReference.arrayOf(DataTypeReference.named("byte"), 4))),
                        null,
                        null,
                        null),
                    RESOLVER));
    assertEquals(
        "array data_type and length are mutually exclusive", arrayLengthBeforeInsert.getMessage());

    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            List.of(new CompositeField("at_four", null, 4, null, DataTypeReference.named("short"))),
            null,
            null,
            null),
        RESOLVER);
    DataTypeComponent inserted = struct.getDefinedComponentAtOrAfterOffset(4);
    assertEquals(4, inserted.getOffset());
    assertEquals("at_four", inserted.getFieldName());
    assertInstanceOf(ShortDataType.class, inserted.getDataType());
    assertEquals(2, inserted.getLength());
  }

  @Test
  void selectorValidationAndLookupErrorsPreserveStructAndUnionMessages() {
    StructureDataType struct = new StructureDataType("SelectorStruct", 8);
    struct.replaceAtOffset(4, IntegerDataType.dataType, 4, "value", null);

    var emptyStructSelector =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                StructMutations.edit(
                    struct,
                    new DataTypePatch.Struct(
                        null,
                        List.of(new CompositeField(null, "renamed", null, null, null)),
                        null,
                        null),
                    RESOLVER));
    assertEquals(
        "struct field selector requires name or offset", emptyStructSelector.getMessage());

    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            null, null, null, List.of(new CompositeField(null, null, 2, null, null))),
        RESOLVER);
    assertEquals("value", struct.getDefinedComponentAtOrAfterOffset(4).getFieldName());

    var structOffsetMiss =
        assertThrows(
            NoSuchElementException.class,
            () ->
                StructMutations.edit(
                    struct,
                    new DataTypePatch.Struct(
                        null,
                        List.of(new CompositeField(null, "renamed", 2, null, null)),
                        null,
                        null),
                    RESOLVER));
    assertEquals("struct field not found", structOffsetMiss.getMessage());

    UnionDataType union = new UnionDataType("SelectorUnion");
    union.add(IntegerDataType.dataType, 4, "value", null);

    var emptyUnionSelector =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                UnionMutations.edit(
                    union,
                    new DataTypePatch.Union(
                        null,
                        List.of(new CompositeField(null, "renamed", null, null, null)),
                        null,
                        null),
                    RESOLVER));
    assertEquals("union field selector requires name", emptyUnionSelector.getMessage());

    var offsetUnionSelector =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                UnionMutations.edit(
                    union,
                    new DataTypePatch.Union(
                        null,
                        List.of(new CompositeField("value", "renamed", 0, null, null)),
                        null,
                        null),
                    RESOLVER));
    assertEquals("union field selector requires name", offsetUnionSelector.getMessage());

    var unionMiss =
        assertThrows(
            NoSuchElementException.class,
            () ->
                UnionMutations.edit(
                    union,
                    new DataTypePatch.Union(
                        null,
                        List.of(new CompositeField("absent", "renamed", null, null, null)),
                        null,
                        null),
                    RESOLVER));
    assertEquals("union field not found", unionMiss.getMessage());

    CompositeFieldMutations.CompositeAccess outOfRangeAccess =
        new CompositeFieldMutations.CompositeAccess() {
          @Override
          public CompositeFieldMutations.CompositeKind kind() {
            return CompositeFieldMutations.CompositeKind.STRUCT;
          }

          @Override
          public Composite composite() {
            return struct;
          }

          @Override
          public List<Integer> locate(CompositeField selector) {
            return List.of(99);
          }

          @Override
          public void replace(
              DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {}
        };

    var outOfRange =
        assertThrows(
            NoSuchElementException.class,
            () ->
                CompositeFieldMutations.renameFields(
                    outOfRangeAccess,
                    List.of(new CompositeField("value", "renamed", null, null, null)),
                    RESOLVER));
    assertEquals("struct field ordinal out of range: 99", outOfRange.getMessage());
  }

  @Test
  void updateFieldsReplacesStructAndUnionComponentsInPlacePreservingOrderAndComments() {
    StructureDataType struct = new StructureDataType("ReplaceStruct", 0);
    struct.setPackingEnabled(true);
    struct.add(ByteDataType.dataType, 1, "first", "c0");
    struct.add(ShortDataType.dataType, 2, "middle", "c1");
    struct.add(ByteDataType.dataType, 1, "last", "c2");

    StructMutations.edit(
        struct,
        new DataTypePatch.Struct(
            null,
            null,
            List.of(
                new CompositeField(
                    null, "middle_int", 2, null, DataTypeReference.named("int")),
                new CompositeField("last", "last_only", null, null, null)),
            null),
        RESOLVER);

    assertEquals(3, struct.getNumComponents());
    assertEquals("first", struct.getComponent(0).getFieldName());
    DataTypeComponent replacedStructField = struct.getComponent(1);
    assertEquals("middle_int", replacedStructField.getFieldName());
    assertInstanceOf(IntegerDataType.class, replacedStructField.getDataType());
    assertEquals(4, replacedStructField.getLength());
    assertEquals("c1", replacedStructField.getComment());
    assertEquals("last_only", struct.getComponent(2).getFieldName());
    assertEquals("c2", struct.getComponent(2).getComment());

    StructureDataType unpacked = new StructureDataType("UnpackedReplaceStruct", 8);
    unpacked.replaceAtOffset(0, IntegerDataType.dataType, 4, "head", "hc");
    unpacked.replaceAtOffset(4, IntegerDataType.dataType, 4, "tail", "tc");
    StructMutations.edit(
        unpacked,
        new DataTypePatch.Struct(
            null,
            null,
            List.of(
                new CompositeField("head", "head_short", null, null, DataTypeReference.named("short"))),
            null),
        RESOLVER);
    assertEquals("head_short", unpacked.getComponent(0).getFieldName());
    assertInstanceOf(ShortDataType.class, unpacked.getComponent(0).getDataType());
    assertEquals(2, unpacked.getComponent(0).getLength());
    assertEquals("hc", unpacked.getComponent(0).getComment());
    assertEquals("tail", unpacked.getDefinedComponentAtOrAfterOffset(4).getFieldName());

    UnionDataType union = new UnionDataType("ReplaceUnion");
    union.add(ByteDataType.dataType, 1, "u0", "uc0");
    union.add(ShortDataType.dataType, 2, "u1", "uc1");
    union.add(ByteDataType.dataType, 1, "u2", "uc2");

    UnionMutations.edit(
        union,
        new DataTypePatch.Union(
            null,
            null,
            List.of(
                new CompositeField("u1", "u1_int", null, null, DataTypeReference.named("int")),
                new CompositeField("u2", "u2_only", null, null, null)),
            null),
        RESOLVER);

    assertEquals(3, union.getNumComponents());
    assertEquals("u0", union.getComponent(0).getFieldName());
    DataTypeComponent replacedUnionField = union.getComponent(1);
    assertEquals("u1_int", replacedUnionField.getFieldName());
    assertInstanceOf(IntegerDataType.class, replacedUnionField.getDataType());
    assertEquals(4, replacedUnionField.getLength());
    assertEquals("uc1", replacedUnionField.getComment());
    assertEquals("u2_only", union.getComponent(2).getFieldName());
    assertEquals("uc2", union.getComponent(2).getComment());
  }
}
