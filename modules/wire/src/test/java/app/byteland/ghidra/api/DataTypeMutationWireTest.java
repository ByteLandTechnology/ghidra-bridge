package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class DataTypeMutationWireTest {

  @Test
  void upsertAndCreateValidateFullLayoutsAcrossAllKinds() throws Exception {
    RecordingDataTypeService service = new RecordingDataTypeService();
    AtomicInteger transactions = new AtomicInteger();
    ApiRegistry registry = registryFor(service, transactions);

    Map<String, Object> structFieldWithNullComment = new LinkedHashMap<>();
    structFieldWithNullComment.put("name", "flags");
    structFieldWithNullComment.put("offset", 8);
    structFieldWithNullComment.put("data_type", Map.of("kind", "named", "name", "uint"));
    structFieldWithNullComment.put("comment", null);

    Map<String, Object> structResource =
        Map.of(
            "kind",
            "struct",
            "category_path",
            "/net",
            "name",
            "Packet",
            "size",
            16,
            "fields",
            List.of(
                Map.of(
                    "name",
                    "magic",
                    "offset",
                    0,
                    "length",
                    4,
                    "data_type",
                    Map.of("kind", "named", "name", "uint"),
                    "comment",
                    "Packet header magic"),
                structFieldWithNullComment));

    registry.dispatch("data_type.upsert", Map.of("resource", structResource));
    assertEquals(1, transactions.get());
    RecordingDataTypeService.CreateCall structCall = service.lastCreate.get();
    assertEquals("/net", structCall.categoryPath());
    assertEquals(DataTypeResource.Kind.STRUCT, structCall.kind());
    assertEquals("Packet", structCall.name());
    assertEquals(16, structCall.size());
    assertEquals(2, structCall.fields().size());
    assertEquals("Packet header magic", structCall.fields().get(0).comment());
    assertTrue(structCall.fields().get(0).hasComment());
    assertNull(structCall.fields().get(1).comment());
    assertTrue(structCall.fields().get(1).hasComment());

    Map<String, Object> unionResource =
        Map.of(
            "kind",
            "union",
            "category_path",
            "/net",
            "name",
            "Payload",
            "fields",
            List.of(
                Map.of(
                    "name",
                    "as_u32",
                    "data_type",
                    Map.of("kind", "named", "name", "uint"),
                    "comment",
                    "Word view")));
    registry.dispatch("data_type.upsert", Map.of("resource", unionResource));
    assertEquals(DataTypeResource.Kind.UNION, service.lastCreate.get().kind());
    assertEquals("Word view", service.lastCreate.get().fields().getFirst().comment());

    Map<String, Object> enumValueCleared = new LinkedHashMap<>();
    enumValueCleared.put("name", "STOPPED");
    enumValueCleared.put("value", 2);
    enumValueCleared.put("comment", null);
    Map<String, Object> enumResource =
        Map.of(
            "kind",
            "enum",
            "category_path",
            "/net",
            "name",
            "State",
            "size",
            4,
            "values",
            List.of(
                Map.of("name", "IDLE", "value", 0, "comment", "Initial state"), enumValueCleared));
    registry.dispatch("data_type.create", Map.of("resource", enumResource));
    RecordingDataTypeService.CreateCall enumCall = service.lastCreate.get();
    assertEquals(DataTypeResource.Kind.ENUM, enumCall.kind());
    assertEquals(2, enumCall.values().size());
    assertEquals("Initial state", enumCall.values().get(0).comment());
    assertTrue(enumCall.values().get(0).hasComment());
    assertNull(enumCall.values().get(1).comment());
    assertTrue(enumCall.values().get(1).hasComment());

    registry.dispatch(
        "data_type.upsert",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "typedef",
                "category_path",
                "/net",
                "name",
                "PacketPtr",
                "base_type",
                Map.of("kind", "pointer", "target", Map.of("kind", "named", "name", "/net/Packet")))));
    assertEquals(DataTypeResource.Kind.TYPEDEF, service.lastCreate.get().kind());
    assertEquals(
        DataTypeReference.pointerTo(DataTypeReference.named("/net/Packet")),
        service.lastCreate.get().baseType());

    registry.dispatch(
        "data_type.upsert",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "function",
                "category_path",
                "/net",
                "name",
                "Handler",
                "signature",
                Map.of(
                    "return_type",
                    Map.of("kind", "named", "name", "int"),
                    "parameters",
                    List.of(
                        Map.of(
                            "name",
                            "pkt",
                            "data_type",
                            Map.of(
                                "kind",
                                "pointer",
                                "target",
                                Map.of("kind", "named", "name", "/net/Packet")))),
                    "calling_convention",
                    "default",
                    "has_var_args",
                    false,
                    "has_no_return",
                    false))));
    assertEquals(DataTypeResource.Kind.FUNCTION, service.lastCreate.get().kind());

    // Union resource fields reject fixed offsets at schema level.
    ApiException unionOffsetError =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.upsert",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "union",
                            "name",
                            "BadUnion",
                            "fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "x",
                                    "offset",
                                    0,
                                    "data_type",
                                    Map.of("kind", "named", "name", "int")))))));
    assertEquals(400, unionOffsetError.status());

    // Create rejects a path that exists with 409, while upsert replaces it.
    service.existingOnPrecheck = true;
    ApiException createConflict =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("data_type.create", Map.of("resource", structResource)));
    assertEquals(409, createConflict.status());
    assertEquals("data_type_exists", createConflict.error().code());
    assertDoesNotThrow(
        () -> registry.dispatch("data_type.upsert", Map.of("resource", structResource)));
  }

  @Test
  void patchDecodesPreserveOffsetsNullableCommentsAndTypedef() throws Exception {
    RecordingDataTypeService service = new RecordingDataTypeService();
    service.existingOnPrecheck = true;
    ApiRegistry registry = registryFor(service, new AtomicInteger());

    // Default preserve_offsets is true when omitted.
    Map<String, Object> clearedCommentField = new LinkedHashMap<>();
    clearedCommentField.put("name", "flags");
    clearedCommentField.put("comment", null);

    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/net/Packet"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "update_fields",
                List.of(
                    Map.of("name", "magic", "comment", "Updated comment"),
                    clearedCommentField,
                    Map.of("name", "len", "length", 4)))));
    DataTypePatch.Struct defaultStructPatch =
        assertInstanceOf(DataTypePatch.Struct.class, service.lastPatch.get());
    assertTrue(defaultStructPatch.preserveOffsets());
    assertEquals("Updated comment", defaultStructPatch.updateFields().get(0).comment());
    assertTrue(defaultStructPatch.updateFields().get(0).hasComment());
    assertNull(defaultStructPatch.updateFields().get(1).comment());
    assertTrue(defaultStructPatch.updateFields().get(1).hasComment());
    assertNull(defaultStructPatch.updateFields().get(2).comment());
    assertFalse(defaultStructPatch.updateFields().get(2).hasComment());

    // Explicit preserve_offsets: false selects offset shift mode.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/net/Packet"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "preserve_offsets",
                false,
                "remove_fields",
                List.of(Map.of("offset", 0)))));
    DataTypePatch.Struct shiftingPatch =
        assertInstanceOf(DataTypePatch.Struct.class, service.lastPatch.get());
    assertFalse(shiftingPatch.preserveOffsets());

    // Typedef patch decodes base_type.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/net/PacketAlias"),
            "patch",
            Map.of("kind", "typedef", "base_type", Map.of("kind", "named", "name", "/net/Packet"))));
    DataTypePatch.Typedef typedefPatch =
        assertInstanceOf(DataTypePatch.Typedef.class, service.lastPatch.get());
    assertEquals(DataTypeReference.named("/net/Packet"), typedefPatch.baseType());

    // Absent base_type on typedef patch fails schema validation with 400.
    ApiException invalidTypedefPatch =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/net/PacketAlias"),
                        "patch",
                        Map.of("kind", "typedef"))));
    assertEquals(400, invalidTypedefPatch.status());

    // Validation exception target normalizes to JSON Pointer.
    ApiFailures.Failure overlapFailure =
        ApiFailures.normalize(
            new DataTypeMutationValidationException(
                "resource.fields[1].offset", "overlapping field"));
    assertEquals(400, overlapFailure.status());
    assertEquals("validation_failed", overlapFailure.error().code());
    assertEquals("/resource/fields/1/offset", overlapFailure.error().target());
  }

  private static ApiRegistry registryFor(DataTypeService dataTypes, AtomicInteger transactions) {
    TransactionRunner runner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            transactions.incrementAndGet();
            try {
              return operation.execute();
            } catch (RuntimeException runtime) {
              throw runtime;
            } catch (Exception checked) {
              throw new RuntimeException(checked);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            idleAnalysis(),
            unused(DecompilationService.class),
            unused(SymbolService.class),
            dataTypes,
            runner,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  private static AnalysisService idleAnalysis() {
    return (AnalysisService)
        Proxy.newProxyInstance(
            AnalysisService.class.getClassLoader(),
            new Class<?>[] {AnalysisService.class},
            (proxy, method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError("unexpected call: " + method.getName());
            }));
  }

  private static final class RecordingDataTypeService implements DataTypeService {
    private final AtomicReference<CreateCall> lastCreate = new AtomicReference<>();
    private final AtomicReference<DataTypePatch> lastPatch = new AtomicReference<>();
    private boolean existingOnPrecheck;
    private DataTypeResource createdResource;

    @Override
    public Page<DataTypeCategoryResource> listCategories(
        String categoryPath, int limit, String cursor) {
      throw new AssertionError("unexpected call");
    }

    @Override
    public DataTypeResource getDataType(String path) {
      if (createdResource != null && createdResource.path().equals(path)) {
        DataTypeResource returned = createdResource;
        createdResource = null;
        return returned;
      }
      if (existingOnPrecheck) {
        return new DataTypeResource(
            path, "Existing", "/net", DataTypeResource.Kind.STRUCT, 4, "", 4, List.of(), null, null, null);
      }
      throw new NoSuchElementException(path);
    }

    @Override
    public Page<DataTypeResource> searchDataTypes(
        String query, String categoryPath, String kind, int limit, String cursor) {
      throw new AssertionError("unexpected call");
    }

    @Override
    public void createDataType(
        String categoryPath,
        DataTypeResource.Kind kind,
        String name,
        DataTypeReference baseType,
        int size,
        FunctionSignature signature) {
      throw new AssertionError("expected 8-argument createDataType overload");
    }

    @Override
    public void createDataType(
        String categoryPath,
        DataTypeResource.Kind kind,
        String name,
        DataTypeReference baseType,
        int size,
        List<DataTypePatch.CompositeField> fields,
        List<DataTypePatch.EnumValue> values,
        FunctionSignature signature) {
      lastCreate.set(
          new CreateCall(categoryPath, kind, name, baseType, size, fields, values, signature));
      String normalizedCategory =
          categoryPath == null || categoryPath.isBlank() || "/".equals(categoryPath)
              ? ""
              : categoryPath;
      createdResource =
          new DataTypeResource(
              normalizedCategory + "/" + name,
              name,
              categoryPath == null ? "/" : categoryPath,
              kind,
              Math.max(size, 4),
              "",
              Math.max(size, 4),
              List.of(),
              null,
              signature,
              baseType);
    }

    @Override
    public void patchDataType(String path, DataTypePatch patch) {
      lastPatch.set(patch);
    }

    @Override
    public boolean deleteDataType(String path) {
      return true;
    }

    record CreateCall(
        String categoryPath,
        DataTypeResource.Kind kind,
        String name,
        DataTypeReference baseType,
        int size,
        List<DataTypePatch.CompositeField> fields,
        List<DataTypePatch.EnumValue> values,
        FunctionSignature signature) {}
  }
}
