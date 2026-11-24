package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
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
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import utility.application.DummyApplicationLayout;

class StructBoundsAdapterTest {
  @BeforeAll
  static void initializeGhidra() throws IOException {
    if (!Application.isInitialized()) {
      ApplicationConfiguration configuration = new ApplicationConfiguration();
      configuration.setInitializeLogging(false);
      Application.initializeApplication(new DummyApplicationLayout("GhidraTest"), configuration);
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void executesSparseStructCreatePatchGetAndDeleteWithoutOverflow() throws Exception {
    try (StandAloneDataTypeManager standAlone = new StandAloneDataTypeManager("test")) {
      int tx = standAlone.startTransaction("sparse-struct-test");
      try {
        standAlone.addDataType(ByteDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
        standAlone.addDataType(QWordDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
        ApiRegistry registry = registryForManager(standAlone);

        registry.dispatch(
            "data_type.create",
            Map.of("resource", Map.of("kind", "struct", "name", "marker_patch", "size", 0)));

        Map<String, Object> createCall =
            JsonUtil.parseObject(
                "{\"operation\":\"create\",\"params\":{\"resource\":"
                    + "{\"kind\":\"struct\",\"name\":\"marker_create\",\"size\":25000}}}");
        Map<String, Object> created =
            (Map<String, Object>)
                registry.dispatch(
                    "data_type.create", (Map<String, Object>) createCall.get("params"));
        assertEquals("/marker_create", created.get("path"));
        assertEquals(25000, ((Number) created.get("size")).intValue());
        assertEquals(List.of(), created.get("fields"));

        Map<String, Object> patchAddCall =
            JsonUtil.parseObject(
                "{\"operation\":\"patch\",\"params\":{\"selector\":{\"path\":\"/marker_patch\"},"
                    + "\"patch\":{\"kind\":\"struct\",\"add_fields\":[{\"name\":\"tail_byte\","
                    + "\"offset\":25000,\"data_type\":{\"kind\":\"named\",\"name\":\"byte\"}}]}}}");
        Map<String, Object> patched =
            (Map<String, Object>)
                registry.dispatch(
                    "data_type.patch", (Map<String, Object>) patchAddCall.get("params"));
        assertEquals(25001, ((Number) patched.get("size")).intValue());
        List<Map<String, Object>> fields = (List<Map<String, Object>>) patched.get("fields");
        assertEquals(1, fields.size());
        assertEquals("tail_byte", fields.getFirst().get("name"));
        assertEquals(25000, ((Number) fields.getFirst().get("ordinal")).intValue());
        assertEquals(25000, ((Number) fields.getFirst().get("offset")).intValue());

        Map<String, Object> patchRemoveMissing =
            JsonUtil.parseObject(
                "{\"operation\":\"patch\",\"params\":{\"selector\":{\"path\":\"/marker_patch\"},"
                    + "\"patch\":{\"kind\":\"struct\",\"remove_fields\":"
                    + "[{\"name\":\"missing_field_0\"}]}}}");
        Map<String, Object> unchanged =
            (Map<String, Object>)
                registry.dispatch(
                    "data_type.patch", (Map<String, Object>) patchRemoveMissing.get("params"));
        assertEquals(1, ((List<?>) unchanged.get("fields")).size());

        // Verify replace and delete preserve full component ordinals on sparse structs.
        Map<String, Object> updated =
            (Map<String, Object>)
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/marker_patch"),
                        "patch",
                        Map.of(
                            "kind",
                            "struct",
                            "update_fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "tail_byte",
                                    "new_name",
                                    "tail_qword",
                                    "data_type",
                                    Map.of("kind", "named", "name", "qword"))))));
        List<Map<String, Object>> updatedFields =
            (List<Map<String, Object>>) updated.get("fields");
        assertEquals(1, updatedFields.size());
        assertEquals("tail_qword", updatedFields.getFirst().get("name"));
        assertEquals(25000, ((Number) updatedFields.getFirst().get("ordinal")).intValue());
        assertEquals(8, ((Number) updatedFields.getFirst().get("length")).intValue());

        Map<String, Object> cleared =
            (Map<String, Object>)
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/marker_patch"),
                        "patch",
                        Map.of(
                            "kind",
                            "struct",
                            "remove_fields",
                            List.of(Map.of("name", "tail_qword")))));
        assertEquals(List.of(), cleared.get("fields"));
      } finally {
        standAlone.endTransaction(tx, true);
      }
    }
  }

  @Test
  void sparseDescribeAddAndNameRemoveNeverCallPerByteGetComponent() {
    StructureDataType delegate = new StructureDataType(CategoryPath.ROOT, "sparse", 25_000);
    Structure guarded = forbidPerByteGetComponent(delegate);
    Function<DataTypeReference, DataType> resolver = ref -> ByteDataType.dataType;

    DataTypeResource initial = DataTypeDescriptions.detail(guarded);
    assertEquals(25_000, initial.size());
    assertEquals(List.of(), initial.fields());

    StructMutations.edit(
        guarded,
        new DataTypePatch.Struct(
            List.of(
                new DataTypePatch.CompositeField(
                    "tail_byte", null, 25_000, null, DataTypeReference.named("byte"))),
            null,
            null,
            null),
        resolver);

    DataTypeResource withTail = DataTypeDescriptions.detail(guarded);
    assertEquals(25_001, withTail.size());
    assertEquals(1, withTail.fields().size());
    assertEquals(25_000, withTail.fields().getFirst().ordinal());

    StructMutations.edit(
        guarded,
        new DataTypePatch.Struct(
            null,
            null,
            null,
            List.of(new DataTypePatch.CompositeField("missing_field_0", null, null, null, null))),
        resolver);
    assertEquals(1, DataTypeDescriptions.detail(guarded).fields().size());
  }

  @Test
  void enforcesAdapterStructSizeOverflowAndDefinedFieldLimits() {
    try (StandAloneDataTypeManager manager = new StandAloneDataTypeManager("bounds")) {
      int tx = manager.startTransaction("bounds");
      try {
        manager.addDataType(ByteDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
        manager.addDataType(QWordDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
        Function<DataTypeReference, DataType> resolver =
            ref -> GhidraDataTypeReferences.resolve(manager, ref);

        DataTypeMutationValidationException createTooLarge =
            assertThrows(
                DataTypeMutationValidationException.class,
                () ->
                    DataTypeMutations.createDataType(
                        manager,
                        "/",
                        DataTypeResource.Kind.STRUCT,
                        "too_large",
                        null,
                        DataTypeService.MAX_STRUCT_SIZE + 1,
                        null,
                        resolver));
        assertEquals(400, ApiFailures.normalize(createTooLarge).status());
        assertEquals("/resource/size", createTooLarge.target());

        // A zero-length struct accepts an append of MAX_STRUCT_SIZE bytes.
        StructureDataType zeroStruct = new StructureDataType(CategoryPath.ROOT, "zero", 0);
        StructMutations.edit(
            zeroStruct,
            new DataTypePatch.Struct(
                List.of(
                    new DataTypePatch.CompositeField(
                        "full_block",
                        null,
                        null,
                        DataTypeService.MAX_STRUCT_SIZE,
                        DataTypeReference.named("byte"))),
                null,
                null,
                null),
            resolver);
        assertEquals(DataTypeService.MAX_STRUCT_SIZE, zeroStruct.getLength());

        // One additional byte exceeds MAX_STRUCT_SIZE and fails validation.
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                StructMutations.edit(
                    zeroStruct,
                    new DataTypePatch.Struct(
                        List.of(
                            new DataTypePatch.CompositeField(
                                "extra", null, null, 1, DataTypeReference.named("byte"))),
                        null,
                        null,
                        null),
                    resolver));

        // An insert at offset 0 past MAX_STRUCT_SIZE fails validation.
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                StructMutations.edit(
                    zeroStruct,
                    new DataTypePatch.Struct(
                        List.of(
                            new DataTypePatch.CompositeField(
                                "shift_extra", null, 0, 1, DataTypeReference.named("byte"))),
                        null,
                        null,
                        null),
                    resolver));

        // Integer overflow in offset + length maps to 400 validation failure.
        StructureDataType overflowStruct = new StructureDataType(CategoryPath.ROOT, "ovf", 0);
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
                        resolver));
        assertEquals(400, ApiFailures.normalize(overflowError).status());
        assertEquals("/patch/add_fields/0/offset", overflowError.target());

        // A tail field update past MAX_STRUCT_SIZE fails validation.
        StructureDataType nearMax = new StructureDataType(CategoryPath.ROOT, "near_max", 0);
        nearMax.insertAtOffset(
            DataTypeService.MAX_STRUCT_SIZE - 4, ByteDataType.dataType, 4, "tail", null);
        assertThrows(
            DataTypeMutationValidationException.class,
            () ->
                StructMutations.edit(
                    nearMax,
                    new DataTypePatch.Struct(
                        null,
                        null,
                        List.of(
                            new DataTypePatch.CompositeField(
                                "tail", null, null, 8, DataTypeReference.named("qword"))),
                        null),
                    ref -> QWordDataType.dataType));
      } finally {
        manager.endTransaction(tx, true);
      }
    }
  }

  @Test
  void enforcesOneThousandDefinedComponentCapInMutationsAndDescriptions() {
    StructureDataType dense = new StructureDataType(CategoryPath.ROOT, "dense", 0);
    for (int index = 0; index < DataTypeService.MAX_DEFINED_COMPONENTS; index++) {
      dense.add(ByteDataType.dataType, 1, "f_" + index, null);
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
                            "f_overflow", null, null, 1, DataTypeReference.named("byte"))),
                    null,
                    null,
                    null),
                ref -> ByteDataType.dataType));

    dense.add(ByteDataType.dataType, 1, "f_1000", null);
    IllegalArgumentException tooManyDefined =
        assertThrows(IllegalArgumentException.class, () -> DataTypeDescriptions.detail(dense));
    assertEquals(400, ApiFailures.normalize(tooManyDefined).status());
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
              if ("getDefinedComponents".equals(method.getName())) {
                DataTypeComponent[] defined = delegate.getDefinedComponents();
                return defined;
              }
              try {
                return method.invoke(delegate, args);
              } catch (InvocationTargetException ex) {
                throw ex.getTargetException();
              }
            });
  }

  private static ApiRegistry registryForManager(DataTypeManager delegateManager) {
    ProgramBasedDataTypeManager programManager =
        (ProgramBasedDataTypeManager)
            Proxy.newProxyInstance(
                ProgramBasedDataTypeManager.class.getClassLoader(),
                new Class<?>[] {ProgramBasedDataTypeManager.class},
                (proxy, method, args) -> {
                  try {
                    return method.invoke(delegateManager, args);
                  } catch (InvocationTargetException ex) {
                    throw ex.getTargetException();
                  }
                });
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) -> {
                  if ("getDataTypeManager".equals(method.getName())) return programManager;
                  throw new AssertionError(method.getName());
                });
    GhidraScript script =
        new GhidraScript() {
          {
            set(program, TaskMonitor.DUMMY);
          }

          @Override
          protected void run() {}
        };
    GhidraSession session = new GhidraSession(script);
    DataTypeService dataTypeService = new DataTypeServiceImpl(session);
    AnalysisService analysis =
        unusedWithIdleAnalysis();
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException ex) {
              throw ex;
            } catch (Exception ex) {
              throw new RuntimeException(ex);
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
            dataTypeService,
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  private static AnalysisService unusedWithIdleAnalysis() {
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
              throw new AssertionError(method.getName());
            }));
  }
}
