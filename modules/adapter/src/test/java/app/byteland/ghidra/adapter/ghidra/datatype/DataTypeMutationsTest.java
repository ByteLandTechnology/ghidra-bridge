package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class DataTypeMutationsTest {
  private StandAloneDataTypeManager manager;
  private int transactionId;
  private DataTypeServiceImpl service;
  private ApiRegistry registry;

  @BeforeAll
  static void initializeGhidra() {
    GhidraTestSupport.x64Language();
  }

  @BeforeEach
  void setUp() {
    manager = new StandAloneDataTypeManager("test");
    transactionId = manager.startTransaction("test");
    for (DataType builtin :
        List.of(
            ByteDataType.dataType,
            IntegerDataType.dataType,
            UnsignedShortDataType.dataType,
            UnsignedIntegerDataType.dataType,
            UnsignedLongLongDataType.dataType)) {
      manager.addDataType(builtin, DataTypeConflictHandler.DEFAULT_HANDLER);
    }
    service = new DataTypeServiceImpl(manager);
    AnalysisService analysis =
        unusedWith(
            AnalysisService.class,
            "getStatus",
            new AnalysisResource(
                AnalysisResource.Kind.GHIDRA,
                AnalysisResource.Status.IDLE,
                false,
                null,
                null,
                null,
                null));
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException runtime) {
              throw runtime;
            } catch (Exception checked) {
              throw new IllegalStateException(checked);
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
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            service,
            transactionRunner,
            "test-session");
    registry = new ApiRegistry(services, "test-session", Map::of, () -> {});
  }

  @AfterEach
  void tearDown() {
    if (manager != null) {
      manager.endTransaction(transactionId, true);
      manager.close();
    }
  }

  @Test
  void unpackedStructPatchesPreserveFixedOffsetsAndClearRemovedFields() throws Exception {
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of("kind", "struct", "category_path", "/Test", "name", "Packet", "size", 0)));

    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Packet"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "add_fields",
                List.of(
                    Map.of(
                        "name",
                        "magic",
                        "offset",
                        0,
                        "data_type",
                        named("uint"),
                        "comment",
                        "header magic"),
                    Map.of(
                        "name",
                        "payload_len",
                        "offset",
                        8,
                        "data_type",
                        named("ushort"),
                        "comment",
                        "payload bytes")))));

    DataTypeResource afterSparseAdd = service.getDataType("/Test/Packet");
    assertEquals(10, afterSparseAdd.size());
    assertEquals(2, afterSparseAdd.fields().size());
    assertField(afterSparseAdd.fields().get(0), "magic", 0, 4, false, "header magic");
    assertField(afterSparseAdd.fields().get(1), "payload_len", 8, 2, false, "payload bytes");
    assertEquals(5, afterSparseAdd.fields().get(1).ordinal());
    Structure rawPacket = (Structure) manager.getDataType("/Test/Packet");
    for (int offset = 4; offset < 8; offset++) {
      assertTrue(rawPacket.getComponentAt(offset).isUndefined());
    }

    // Populate an inner gap with `add_fields` and keep `payload_len` at offset 8.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Packet"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "add_fields",
                List.of(
                    Map.of(
                        "name",
                        "flags",
                        "offset",
                        4,
                        "data_type",
                        named("ushort"),
                        "comment",
                        "packet flags")))));

    DataTypeResource afterGapFill = service.getDataType("/Test/Packet");
    assertEquals(10, afterGapFill.size());
    assertEquals(3, afterGapFill.fields().size());
    assertField(findFieldByOffset(afterGapFill, 0), "magic", 0, 4, false, "header magic");
    assertField(findFieldByOffset(afterGapFill, 4), "flags", 4, 2, false, "packet flags");
    assertTrue(rawPacket.getComponentAt(6).isUndefined());
    assertTrue(rawPacket.getComponentAt(7).isUndefined());
    assertField(findFieldByOffset(afterGapFill, 8), "payload_len", 8, 2, false, "payload bytes");

    // Field removal on an unpacked struct clears its bytes to undefined and keeps later offsets.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Packet"),
            "patch",
            Map.of("kind", "struct", "remove_fields", List.of(Map.of("name", "magic")))));

    DataTypeResource afterRemove = service.getDataType("/Test/Packet");
    assertEquals(10, afterRemove.size());
    assertEquals(2, afterRemove.fields().size());
    for (int offset = 0; offset < 4; offset++) {
      assertTrue(rawPacket.getComponentAt(offset).isUndefined());
    }
    assertField(findFieldByOffset(afterRemove, 4), "flags", 4, 2, false, "packet flags");
    assertField(findFieldByOffset(afterRemove, 8), "payload_len", 8, 2, false, "payload bytes");
  }

  @Test
  void undefinedSlotsCanBePopulatedExpandedAtTailAndAnnotated() throws Exception {
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of("kind", "struct", "category_path", "/Test", "name", "Slots", "size", 8)));

    // Populate undefined slot at offset 2 and expand undefined slot at offset 6 past initial size.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Slots"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "update_fields",
                List.of(
                    Map.of(
                        "offset",
                        2,
                        "new_name",
                        "kind_code",
                        "data_type",
                        named("ushort"),
                        "comment",
                        "slot two"),
                    Map.of(
                        "offset",
                        6,
                        "new_name",
                        "tail_word",
                        "data_type",
                        named("uint"),
                        "comment",
                        "grows tail")))));

    DataTypeResource populated = service.getDataType("/Test/Slots");
    assertEquals(10, populated.size());
    assertField(findFieldByOffset(populated, 2), "kind_code", 2, 2, false, "slot two");
    assertField(findFieldByOffset(populated, 6), "tail_word", 6, 4, false, "grows tail");

    // Set a new name and comment on an undefined slot without an explicit `data_type`.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Slots"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "rename_fields",
                List.of(
                    Map.of(
                        "offset", 0, "new_name", "reserved_0", "comment", "reserved byte")))));

    DataTypeResource annotated = service.getDataType("/Test/Slots");
    DataTypeResource.Field slotZero = findFieldByOffset(annotated, 0);
    assertEquals("reserved_0", slotZero.name());
    assertEquals(1, slotZero.length());
    assertEquals("reserved byte", slotZero.comment());
  }

  @Test
  void packedStructsAndAppendOnlyAdditionsRemainUnchanged() throws Exception {
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of("kind", "struct", "category_path", "/Test", "name", "Appended", "size", 0)));
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Appended"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "add_fields",
                List.of(
                    Map.of("name", "a", "data_type", named("uint")),
                    Map.of("name", "b", "data_type", named("ushort"))))));
    DataTypeResource appended = service.getDataType("/Test/Appended");
    assertEquals(6, appended.size());
    assertField(appended.fields().get(0), "a", 0, 4, false, null);
    assertField(appended.fields().get(1), "b", 4, 2, false, null);

    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of("kind", "struct", "category_path", "/Test", "name", "Packed", "size", 0)));
    Structure packed = (Structure) manager.getDataType("/Test/Packed");
    packed.setPackingEnabled(true);
    service.patchDataType(
        "/Test/Packed",
        new DataTypePatch.Struct(
            List.of(
                new DataTypePatch.CompositeField(
                    "first", null, null, null, DataTypeReference.named("uint"), "c1", true),
                new DataTypePatch.CompositeField(
                    "second", null, null, null, DataTypeReference.named("uint"), "c2", true)),
            null,
            null,
            null));
    service.patchDataType(
        "/Test/Packed",
        new DataTypePatch.Struct(
            null,
            null,
            null,
            List.of(new DataTypePatch.CompositeField("first", null, null, null, null))));
    DataTypeResource packedAfterDelete = service.getDataType("/Test/Packed");
    assertEquals(4, packedAfterDelete.size());
    assertEquals(1, packedAfterDelete.fields().size());
    assertField(packedAfterDelete.fields().getFirst(), "second", 0, 4, false, "c2");
  }

  @Test
  void overlappingAdditionsAndExpansionsMapToHttp400() throws Exception {
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "struct",
                "category_path",
                "/Test",
                "name",
                "Overlap",
                "fields",
                List.of(
                    Map.of("name", "first", "offset", 0, "data_type", named("uint")),
                    Map.of("name", "second", "offset", 6, "data_type", named("uint"))))));

    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.patch",
                Map.of(
                    "selector",
                    Map.of("path", "/Test/Overlap"),
                    "patch",
                    Map.of(
                        "kind",
                        "struct",
                        "add_fields",
                        List.of(
                            Map.of(
                                "name", "collide", "offset", 0, "data_type", named("byte")))))));

    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.patch",
                Map.of(
                    "selector",
                    Map.of("path", "/Test/Overlap"),
                    "patch",
                    Map.of(
                        "kind",
                        "struct",
                        "add_fields",
                        List.of(
                            Map.of(
                                "name", "spill", "offset", 4, "data_type", named("uint")))))));

    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.patch",
                Map.of(
                    "selector",
                    Map.of("path", "/Test/Overlap"),
                    "patch",
                    Map.of(
                        "kind",
                        "struct",
                        "update_fields",
                        List.of(
                            Map.of(
                                "name", "first", "data_type", named("ulonglong")))))));

    // Verify initial fields stay unchanged after all rejected patches.
    DataTypeResource unchanged = service.getDataType("/Test/Overlap");
    assertEquals(10, unchanged.size());
    assertField(findFieldByOffset(unchanged, 0), "first", 0, 4, false, null);
    assertField(findFieldByOffset(unchanged, 6), "second", 6, 4, false, null);
  }

  @Test
  void memberCommentsRoundTripAcrossStructUnionAndEnum() throws Exception {
    // Union create and comment round-trip (keep on rename or update, edit, and clear with null).
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "union",
                "category_path",
                "/Test",
                "name",
                "ValueUnion",
                "fields",
                List.of(
                    Map.of(
                        "name",
                        "as_u32",
                        "data_type",
                        named("uint"),
                        "comment",
                        "32-bit view"),
                    Map.of("name", "as_u64", "data_type", named("ulonglong"))))));

    DataTypeResource createdUnion = service.getDataType("/Test/ValueUnion");
    assertEquals("32-bit view", createdUnion.fields().get(0).comment());
    assertNull(createdUnion.fields().get(1).comment());

    // Rename without `comment` keeps the prior comment; `update_fields` with `comment` sets it.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/ValueUnion"),
            "patch",
            Map.of(
                "kind",
                "union",
                "rename_fields",
                List.of(Map.of("name", "as_u32", "new_name", "u32_val")),
                "update_fields",
                List.of(Map.of("name", "as_u64", "comment", "64-bit view")))));

    DataTypeResource updatedUnion = service.getDataType("/Test/ValueUnion");
    assertEquals("u32_val", updatedUnion.fields().get(0).name());
    assertEquals("32-bit view", updatedUnion.fields().get(0).comment());
    assertEquals("64-bit view", updatedUnion.fields().get(1).comment());

    // Clear the comment with null and update the field type.
    Map<String, Object> clearFieldComment = new HashMap<>();
    clearFieldComment.put("name", "u32_val");
    clearFieldComment.put("data_type", named("int"));
    clearFieldComment.put("comment", null);
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/ValueUnion"),
            "patch",
            Map.of("kind", "union", "update_fields", List.of(clearFieldComment))));
    assertNull(service.getDataType("/Test/ValueUnion").fields().get(0).comment());

    // Enum create and comment round-trip (add, keep on rename or value update, edit, and clear).
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "enum",
                "category_path",
                "/Test",
                "name",
                "Status",
                "size",
                4,
                "values",
                List.of(
                    Map.of("name", "OK", "value", 0, "comment", "success"),
                    Map.of("name", "ERR", "value", 1)))));

    DataTypeResource createdEnum = service.getDataType("/Test/Status");
    assertEquals("success", createdEnum.values().get(0).comment());
    assertEquals("", createdEnum.values().get(1).comment());

    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Status"),
            "patch",
            Map.of(
                "kind",
                "enum",
                "rename_values",
                List.of(Map.of("name", "OK", "new_name", "STATUS_OK")),
                "update_values",
                List.of(Map.of("name", "ERR", "comment", "general failure")))));

    DataTypeResource updatedEnum = service.getDataType("/Test/Status");
    assertEquals("STATUS_OK", updatedEnum.values().get(0).name());
    assertEquals("success", updatedEnum.values().get(0).comment());
    assertEquals("general failure", updatedEnum.values().get(1).comment());

    Map<String, Object> clearEnumComment = new HashMap<>();
    clearEnumComment.put("name", "STATUS_OK");
    clearEnumComment.put("comment", null);
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Status"),
            "patch",
            Map.of("kind", "enum", "update_values", List.of(clearEnumComment))));
    assertEquals("", service.getDataType("/Test/Status").values().get(0).comment());
  }

  @Test
  void createDataTypeSupportsSelfReferentialInitialFieldsAndCleansUpOnInvalidMembers()
      throws Exception {
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "struct",
                "category_path",
                "/Test",
                "name",
                "Node",
                "fields",
                List.of(
                    Map.of(
                        "name",
                        "value",
                        "offset",
                        0,
                        "data_type",
                        named("uint"),
                        "comment",
                        "payload"),
                    Map.of(
                        "name",
                        "next",
                        "offset",
                        8,
                        "data_type",
                        Map.of("kind", "pointer", "target", named("/Test/Node")),
                        "comment",
                        "next node")))));

    DataTypeResource node = service.getDataType("/Test/Node");
    assertField(findFieldByOffset(node, 0), "value", 0, 4, false, "payload");
    DataTypeResource.Field next = findFieldByOffset(node, 8);
    assertEquals("next", next.name());
    assertEquals("next node", next.comment());
    assertEquals(
        DataTypeReference.pointerTo(DataTypeReference.named("/Test/Node")), next.dataType());

    // Invalid initial fields (union rejects `offset`) must remove the new union.
    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.create",
                Map.of(
                    "resource",
                    Map.of(
                        "kind",
                        "union",
                        "category_path",
                        "/Test",
                        "name",
                        "BrokenUnion",
                        "fields",
                        List.of(
                            Map.of("name", "bad", "offset", 0, "data_type", named("uint")))))));
    assertNull(manager.getDataType("/Test/BrokenUnion"));
  }

  @Test
  void typedefPatchAndUpsertReplaceInPlaceAndRejectCyclicDependencies() throws Exception {
    // Create a typedef with `upsert` and reference it from a struct field.
    registry.dispatch(
        "data_type.upsert",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "typedef",
                "category_path",
                "/Test",
                "name",
                "Handle",
                "base_type",
                named("uint"))));
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "struct",
                "category_path",
                "/Test",
                "name",
                "Holder",
                "fields",
                List.of(Map.of("name", "handle", "offset", 0, "data_type", named("/Test/Handle"))))));

    assertEquals(4, service.getDataType("/Test/Holder").size());

    // Patch `/Test/Handle` in place to `ulonglong` and verify the dependent struct updates.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Test/Handle"),
            "patch",
            Map.of("kind", "typedef", "base_type", named("ulonglong"))));

    DataTypeResource patchedHandle = service.getDataType("/Test/Handle");
    assertEquals(DataTypeReference.named("/ulonglong"), patchedHandle.baseType());
    assertEquals(8, patchedHandle.length());
    DataTypeResource updatedHolder = service.getDataType("/Test/Holder");
    assertEquals(8, updatedHolder.size());
    assertEquals(
        DataTypeReference.named("/Test/Handle"), updatedHolder.fields().getFirst().dataType());

    // Upsert the typedef to `ushort` twice to check idempotence.
    for (int attempt = 0; attempt < 2; attempt++) {
      registry.dispatch(
          "data_type.upsert",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "typedef",
                  "category_path",
                  "/Test",
                  "name",
                  "Handle",
                  "base_type",
                  named("ushort"))));
    }
    assertEquals(DataTypeReference.named("/ushort"), service.getDataType("/Test/Handle").baseType());

    // Function `upsert` keeps its prior behavior.
    registry.dispatch(
        "data_type.upsert",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "function",
                "category_path",
                "/Test",
                "name",
                "Callback",
                "signature",
                Map.of(
                    "return_type",
                    named("int"),
                    "parameters",
                    List.of(Map.of("name", "arg", "data_type", named("/Test/Handle"))),
                    "calling_convention",
                    "default",
                    "has_var_args",
                    false,
                    "has_no_return",
                    false))));
    assertEquals(DataTypeResource.Kind.FUNCTION, service.getDataType("/Test/Callback").kind());

    // Reject direct, indirect, and pointer typedef cycles with HTTP 400 and no `.conflict` types.
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "typedef",
                "category_path",
                "/Test",
                "name",
                "SubHandle",
                "base_type",
                named("/Test/Handle"))));

    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.patch",
                Map.of(
                    "selector",
                    Map.of("path", "/Test/Handle"),
                    "patch",
                    Map.of("kind", "typedef", "base_type", named("/Test/Handle")))));
    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.patch",
                Map.of(
                    "selector",
                    Map.of("path", "/Test/Handle"),
                    "patch",
                    Map.of("kind", "typedef", "base_type", named("/Test/SubHandle")))));
    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.upsert",
                Map.of(
                    "resource",
                    Map.of(
                        "kind",
                        "typedef",
                        "category_path",
                        "/Test",
                        "name",
                        "Handle",
                        "base_type",
                        Map.of("kind", "pointer", "target", named("/Test/SubHandle"))))));

    List<String> names = new ArrayList<>();
    Iterator<DataType> allTypes = manager.getAllDataTypes();
    while (allTypes.hasNext()) names.add(allTypes.next().getPathName());
    assertFalse(names.stream().anyMatch(path -> path.contains(".conflict")), names::toString);

    // Non-typedef path collision on upsert maps to HTTP 400.
    assertBadRequest(
        () ->
            registry.dispatch(
                "data_type.upsert",
                Map.of(
                    "resource",
                    Map.of(
                        "kind",
                        "typedef",
                        "category_path",
                        "/Test",
                        "name",
                        "Holder",
                        "base_type",
                        named("uint")))));

    // Verify `DataTypeDependencyException` from `replaceDataType` maps to HTTP 400.
    TypeDef existingTypedef =
        (TypeDef)
            manager.addDataType(
                new TypedefDataType(
                    new CategoryPath("/Test"),
                    "DepCheck",
                    UnsignedIntegerDataType.dataType,
                    manager),
                DataTypeConflictHandler.DEFAULT_HANDLER);
    DataTypeManager throwingManager =
        (DataTypeManager)
            Proxy.newProxyInstance(
                DataTypeManager.class.getClassLoader(),
                new Class<?>[] {DataTypeManager.class},
                (proxy, method, args) -> {
                  if ("replaceDataType".equals(method.getName())) {
                    throw new DataTypeDependencyException("simulated cycle");
                  }
                  return method.invoke(manager, args);
                });
    IllegalArgumentException dependencyError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                DataTypeMutations.replaceTypedef(
                    throwingManager,
                    existingTypedef,
                    DataTypeReference.named("ulonglong"),
                    ref -> GhidraDataTypeReferences.resolve(manager, ref)));
    assertEquals(400, ApiFailures.normalize(dependencyError).status());
  }

  @Test
  void sparseStructsOmitFillerBytesAvoidPerByteScansAndEnforceBounds() throws Exception {
    // Sparse create with an initial field at offset 25000 stays within `maxItems: 1000`.
    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "struct",
                "category_path",
                "/Test",
                "name",
                "Sparse",
                "size",
                25_000,
                "fields",
                List.of(Map.of("name", "tail_word", "offset", 25_000, "data_type", named("uint"))))));
    DataTypeResource sparse = service.getDataType("/Test/Sparse");
    assertEquals(25_004, sparse.size());
    assertEquals(1, sparse.fields().size());
    assertEquals(25_000, sparse.fields().getFirst().ordinal());
    assertField(sparse.fields().getFirst(), "tail_word", 25_000, 4, false, null);

    // Explicit `Undefined1DataType` component stays in `fields` and default filler bytes do not.
    StructureDataType delegate = new StructureDataType(CategoryPath.ROOT, "GuardedSparse", 25_000);
    delegate.replaceAtOffset(100, Undefined1DataType.dataType, 1, "explicit_undef", "marker");
    Structure guarded = forbidPerByteGetComponent(delegate);
    DataTypeResource describedGuarded = DataTypeDescriptions.detail(guarded);
    assertEquals(25_000, describedGuarded.size());
    assertEquals(1, describedGuarded.fields().size());
    assertField(describedGuarded.fields().getFirst(), "explicit_undef", 100, 1, false, "marker");

    StructMutations.edit(
        guarded,
        new DataTypePatch.Struct(
            List.of(
                new DataTypePatch.CompositeField(
                    "far_tail", null, 25_000, null, DataTypeReference.named("byte"))),
            null,
            null,
            List.of(new DataTypePatch.CompositeField("missing_name", null, null, null, null))),
        ref -> ByteDataType.dataType);
    assertEquals(2, DataTypeDescriptions.detail(guarded).fields().size());

    // Check `MAX_STRUCT_SIZE` across `create`, initial fields, `add_fields`, and integer overflow.
    DataTypeMutationValidationException createTooLarge =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                DataTypeMutations.createDataType(
                    manager,
                    "/Test",
                    DataTypeResource.Kind.STRUCT,
                    "TooLarge",
                    null,
                    DataTypeService.MAX_STRUCT_SIZE + 1,
                    null,
                    ref -> GhidraDataTypeReferences.resolve(manager, ref)));
    assertEquals("/resource/size", createTooLarge.target());
    assertEquals(400, ApiFailures.normalize(createTooLarge).status());

    DataTypeMutationValidationException initialFieldTooLarge =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                service.createDataType(
                    "/Test",
                    DataTypeResource.Kind.STRUCT,
                    "InitialOverflow",
                    null,
                    0,
                    null,
                    List.of(
                        new DataTypePatch.CompositeField(
                            "spill",
                            null,
                            DataTypeService.MAX_STRUCT_SIZE - 2,
                            null,
                            DataTypeReference.named("uint"))),
                    null));
    assertEquals("/resource/fields/0/offset", initialFieldTooLarge.target());
    assertNull(manager.getDataType("/Test/InitialOverflow"));

    StructureDataType overflowStruct = new StructureDataType(CategoryPath.ROOT, "Overflow", 0);
    DataTypeMutationValidationException overflowError =
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                StructMutations.edit(
                    overflowStruct,
                    new DataTypePatch.Struct(
                        List.of(
                            new DataTypePatch.CompositeField(
                                "overflow",
                                null,
                                Integer.MAX_VALUE,
                                4,
                                DataTypeReference.named("byte"))),
                        null,
                        null,
                        null),
                    ref -> ByteDataType.dataType));
    assertEquals("/patch/add_fields/0/offset", overflowError.target());

    // Check `MAX_DEFINED_COMPONENTS` across `add_fields`, undefined-slot updates, and `detail()`.
    StructureDataType dense = new StructureDataType(CategoryPath.ROOT, "Dense", 1_005);
    for (int index = 0; index < DataTypeService.MAX_DEFINED_COMPONENTS; index++) {
      dense.replaceAtOffset(index, ByteDataType.dataType, 1, "f_" + index, null);
    }
    assertEquals(
        DataTypeService.MAX_DEFINED_COMPONENTS, DataTypeDescriptions.detail(dense).fields().size());
    assertThrows(
        DataTypeMutationValidationException.class,
        () ->
            StructMutations.edit(
                dense,
                new DataTypePatch.Struct(
                    List.of(
                        new DataTypePatch.CompositeField(
                            "extra", null, null, 1, DataTypeReference.named("byte"))),
                    null,
                    null,
                    null),
                ref -> ByteDataType.dataType));
    assertThrows(
        DataTypeMutationValidationException.class,
        () ->
            StructMutations.edit(
                dense,
                new DataTypePatch.Struct(
                    null,
                    List.of(
                        new DataTypePatch.CompositeField(
                            null, "promoted_undef", 1_001, null, null, "note", true)),
                    null,
                    null),
                ref -> ByteDataType.dataType));
    dense.replaceAtOffset(1_000, ByteDataType.dataType, 1, "f_1000", null);
    assertThrows(IllegalArgumentException.class, () -> DataTypeDescriptions.detail(dense));

    // Consolidated `CompositeFieldMutations` checks union `offset` before type resolution.
    UnionDataType union = new UnionDataType("OffsetOrderUnion");
    IllegalArgumentException unionOffsetError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                UnionMutations.edit(
                    union,
                    new DataTypePatch.Union(
                        List.of(
                            new DataTypePatch.CompositeField(
                                "bad", null, 0, -1, DataTypeReference.named("missing"))),
                        null,
                        null,
                        null),
                    ignored -> {
                      throw new AssertionError("resolver must not run before union offset check");
                    }));
    assertEquals("union add_fields does not support offset", unionOffsetError.getMessage());

    // Default `CompositeAccess.addField` appends without `offset` and rejects `offset != null`.
    CompositeFieldMutations.CompositeAccess defaultUnionAccess =
        new CompositeFieldMutations.CompositeAccess() {
          @Override
          public CompositeFieldMutations.CompositeKind kind() {
            return CompositeFieldMutations.CompositeKind.UNION;
          }

          @Override
          public ghidra.program.model.data.Composite composite() {
            return union;
          }

          @Override
          public List<Integer> locate(DataTypePatch.CompositeField selector) {
            return CompositeFieldMutations.findOrdinalsByName(union, selector.name());
          }

          @Override
          public void replace(
              DataTypeComponent component, CompositeFieldMutations.Replacement replacement) {}
        };
    CompositeFieldMutations.addFields(
        defaultUnionAccess,
        List.of(new DataTypePatch.CompositeField("ok", null, null, null, null, "note", true)),
        ref -> ByteDataType.dataType);
    assertEquals(1, union.getNumComponents());
    assertEquals("note", union.getComponent(0).getComment());
    IllegalArgumentException defaultOffsetError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                CompositeFieldMutations.addFields(
                    defaultUnionAccess,
                    List.of(new DataTypePatch.CompositeField("bad", null, 0, null, null)),
                    ref -> ByteDataType.dataType));
    assertEquals("union add_fields does not support offset", defaultOffsetError.getMessage());
  }

  private static Structure forbidPerByteGetComponent(Structure delegate) {
    return (Structure)
        Proxy.newProxyInstance(
            Structure.class.getClassLoader(),
            new Class<?>[] {Structure.class},
            (proxy, method, args) -> {
              if ("getComponent".equals(method.getName())) {
                throw new AssertionError("unexpected per-byte getComponent call");
              }
              try {
                return method.invoke(delegate, args);
              } catch (InvocationTargetException ex) {
                throw ex.getTargetException();
              }
            });
  }

  private static Map<String, Object> named(String name) {
    return Map.of("kind", "named", "name", name);
  }

  private static DataTypeResource.Field findFieldByOffset(DataTypeResource resource, int offset) {
    return resource.fields().stream()
        .filter(field -> field.offset() == offset)
        .findFirst()
        .orElseThrow(() -> new AssertionError("No field at offset " + offset));
  }

  private static void assertField(
      DataTypeResource.Field field,
      String expectedName,
      int expectedOffset,
      int expectedLength,
      boolean expectedUndefined,
      String expectedComment) {
    assertNotNull(field);
    assertEquals(expectedName, field.name());
    assertEquals(expectedOffset, field.offset());
    assertEquals(expectedLength, field.length());
    assertEquals(expectedUndefined, field.isUndefined());
    assertEquals(expectedComment, field.comment());
  }

  private static void assertBadRequest(Executable action) {
    Throwable thrown = assertThrows(Throwable.class, action);
    if (thrown instanceof ApiException apiError) {
      assertEquals(400, apiError.status());
      return;
    }
    var normalized = ApiFailures.normalize(thrown);
    assertEquals(400, normalized.status(), () -> "Unexpected failure: " + thrown);
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError("Unexpected call: " + method.getName());
            }));
  }

  private static <T> T unusedWith(Class<T> type, String allowedMethod, Object returnValue) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (allowedMethod.equals(method.getName())) return returnValue;
              throw new AssertionError("Unexpected call: " + method.getName());
            }));
  }
}
