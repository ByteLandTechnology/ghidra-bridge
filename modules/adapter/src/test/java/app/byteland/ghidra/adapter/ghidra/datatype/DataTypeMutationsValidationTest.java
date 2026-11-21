package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import java.lang.reflect.Proxy;
import java.util.List;
import org.junit.jupiter.api.Test;

class DataTypeMutationsValidationTest {

  @Test
  void createDataTypeEmitsParameterRelativeResourcePointers() {
    DataTypeManager manager = managerWithConventions(List.of("__cdecl"));

    DataTypeMutationValidationException missingBaseType =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                DataTypeMutations.createDataType(
                    manager,
                    "/",
                    DataTypeResource.Kind.TYPEDEF,
                    "Alias",
                    null,
                    0,
                    null,
                    ref -> null));
    assertParameterRelativePointer("/resource/base_type", missingBaseType);

    DataTypeMutationValidationException unknownBaseType =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                DataTypeMutations.createDataType(
                    manager,
                    "/",
                    DataTypeResource.Kind.TYPEDEF,
                    "Alias",
                    DataTypeReference.named("missing_t"),
                    0,
                    null,
                    ref -> null));
    assertParameterRelativePointer("/resource/base_type", unknownBaseType);

    DataTypeMutationValidationException unknownCallingConvention =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                DataTypeMutations.createDataType(
                    manager,
                    "/",
                    DataTypeResource.Kind.FUNCTION,
                    "Fn",
                    null,
                    0,
                    new FunctionSignature(
                        DataTypeReference.named("void"), List.of(), "bogus_cc", false, false),
                    ref -> VoidDataType.dataType));
    assertParameterRelativePointer(
        "/resource/signature/calling_convention", unknownCallingConvention);

    DataTypeMutationValidationException unknownReturnType =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                DataTypeMutations.createDataType(
                    manager,
                    "/",
                    DataTypeResource.Kind.FUNCTION,
                    "Fn",
                    null,
                    0,
                    new FunctionSignature(
                        DataTypeReference.named("missing_ret"),
                        List.of(),
                        "default",
                        false,
                        false),
                    ref -> null));
    assertParameterRelativePointer("/resource/signature/return_type", unknownReturnType);

    DataTypeMutationValidationException unknownParameterType =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                DataTypeMutations.createDataType(
                    manager,
                    "/",
                    DataTypeResource.Kind.FUNCTION,
                    "Fn",
                    null,
                    0,
                    new FunctionSignature(
                        DataTypeReference.named("void"),
                        List.of(
                            new FunctionSignature.Parameter(
                                "arg0", DataTypeReference.named("missing_param"))),
                        "default",
                        false,
                        false),
                    ref ->
                        ref instanceof DataTypeReference.Named named
                                && "void".equals(named.name())
                            ? VoidDataType.dataType
                            : null));
    assertParameterRelativePointer(
        "/resource/signature/parameters/0/data_type", unknownParameterType);
  }

  @Test
  void patchMutationsEmitParameterRelativePatchPointers() {
    Structure structure = proxy(Structure.class, (method, args) -> 0);
    DataTypeMutationValidationException badStructAddType =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                StructMutations.edit(
                    structure,
                    new DataTypePatch.Struct(
                        List.of(
                            new DataTypePatch.CompositeField(
                                "f0", null, null, null, DataTypeReference.named("unknown_t"))),
                        null,
                        null,
                        null),
                    ref -> null));
    assertParameterRelativePointer("/patch/add_fields/0/data_type", badStructAddType);

    Union union = proxy(Union.class, (method, args) -> 0);
    DataTypeMutationValidationException badUnionOffset =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                UnionMutations.edit(
                    union,
                    new DataTypePatch.Union(
                        List.of(
                            new DataTypePatch.CompositeField(
                                "f0", null, 4, null, DataTypeReference.named("int"))),
                        null,
                        null,
                        null),
                    ref -> VoidDataType.dataType));
    assertParameterRelativePointer("/patch/add_fields/0/offset", badUnionOffset);

    Enum enumType = proxy(Enum.class, (method, args) -> true);
    DataTypeMutationValidationException badEnumRemove =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                EnumMutations.edit(
                    enumType,
                    new DataTypePatch.EnumPatch(
                        null,
                        List.of(new DataTypePatch.EnumValue(null, null, null)),
                        null,
                        null)));
    assertParameterRelativePointer("/patch/remove_values/0", badEnumRemove);
  }

  private static void assertParameterRelativePointer(
      String expectedPointer, DataTypeMutationValidationException exception) {
    assertEquals(400, exception.status());
    assertEquals("validation_failed", exception.code());
    assertEquals(expectedPointer, exception.target());
    var normalized = ApiFailures.normalize(exception);
    assertEquals(400, normalized.status());
    assertEquals(expectedPointer, normalized.error().target());
    assertFalse(normalized.error().target().startsWith("/params/"));
  }

  private static DataTypeManager managerWithConventions(List<String> conventions) {
    return proxy(
        DataTypeManager.class,
        (method, args) -> {
          if ("getKnownCallingConventionNames".equals(method)) {
            return conventions;
          }
          if ("getDataOrganization".equals(method)) {
            return null;
          }
          return null;
        });
  }

  private interface Invocation {
    Object invoke(String method, Object[] args);
  }

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> invocation.invoke(method.getName(), args)));
  }
}
