package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
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
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class DataTypeMutationTest {
  @Test
  void createDecodesInitialMembersAndRejectsMismatchedSchemas() throws Exception {
    AtomicReference<Object[]> capturedCreate = new AtomicReference<>();
    Map<String, DataTypeResource> store = new HashMap<>();
    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              switch (method) {
                case "getDataType" -> {
                  DataTypeResource found = store.get((String) args[0]);
                  if (found == null) throw new NoSuchElementException("not found: " + args[0]);
                  return found;
                }
                case "createDataType" -> {
                  capturedCreate.set(args);
                  String category = (String) args[0];
                  DataTypeResource.Kind kind = (DataTypeResource.Kind) args[1];
                  String name = (String) args[2];
                  String path = ("/".equals(category) ? "/" : category + "/") + name;
                  store.put(
                      path,
                      new DataTypeResource(
                          path, name, category, kind, 8, "", 8, List.of(), null, null, null));
                  return null;
                }
                default -> throw new AssertionError(method);
              }
            });
    ApiRegistry registry = registryFor(dataTypes);

    Map<String, Object> clearedCommentField = new HashMap<>();
    clearedCommentField.put("name", "pad");
    clearedCommentField.put("offset", 4);
    clearedCommentField.put("comment", null);

    registry.dispatch(
        "data_type.create",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "struct",
                "category_path",
                "/Types",
                "name",
                "Header",
                "fields",
                List.of(
                    Map.of(
                        "name",
                        "magic",
                        "offset",
                        0,
                        "data_type",
                        Map.of("kind", "named", "name", "uint"),
                        "comment",
                        "magic word"),
                    clearedCommentField))));

    Object[] createArgs = capturedCreate.get();
    assertEquals("/Types", createArgs[0]);
    assertEquals(DataTypeResource.Kind.STRUCT, createArgs[1]);
    assertEquals("Header", createArgs[2]);
    @SuppressWarnings("unchecked")
    List<DataTypePatch.CompositeField> fields = (List<DataTypePatch.CompositeField>) createArgs[6];
    assertEquals(2, fields.size());
    assertEquals("magic", fields.get(0).name());
    assertEquals(0, fields.get(0).offset());
    assertEquals("magic word", fields.get(0).comment());
    assertTrue(fields.get(0).commentPresent());
    assertNull(fields.get(1).comment());
    assertTrue(fields.get(1).commentPresent());

    // Duplicate create returns 409 `data_type_exists`.
    ApiException duplicate =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of("kind", "struct", "category_path", "/Types", "name", "Header"))));
    assertEquals(409, duplicate.status());

    // Enum resource rejects struct fields; struct resource rejects enum values.
    ApiException invalidEnumFields =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of("kind", "enum", "name", "BadEnum", "fields", List.of()))));
    assertEquals(400, invalidEnumFields.status());

    ApiException invalidStructValues =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of("kind", "struct", "name", "BadStruct", "values", List.of()))));
    assertEquals(400, invalidStructValues.status());
  }

  @Test
  void patchAndUpsertDecodeMemberCommentsAndTypedefUpdates() throws Exception {
    AtomicReference<DataTypePatch> lastPatch = new AtomicReference<>();
    AtomicReference<Object[]> lastCreate = new AtomicReference<>();
    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              switch (method) {
                case "patchDataType" -> {
                  lastPatch.set((DataTypePatch) args[1]);
                  return null;
                }
                case "createDataType" -> {
                  lastCreate.set(args);
                  return null;
                }
                case "getDataType" -> {
                  String path = (String) args[0];
                  return new DataTypeResource(
                      path,
                      "Handle",
                      "/Types",
                      DataTypeResource.Kind.TYPEDEF,
                      8,
                      "",
                      null,
                      null,
                      null,
                      null,
                      DataTypeReference.named("/ulonglong"));
                }
                default -> throw new AssertionError(method);
              }
            });
    ApiRegistry registry = registryFor(dataTypes);

    Map<String, Object> explicitNullComment = new HashMap<>();
    explicitNullComment.put("name", "a");
    explicitNullComment.put("comment", null);

    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Types/Record"),
            "patch",
            Map.of(
                "kind",
                "struct",
                "rename_fields",
                List.of(Map.of("name", "old", "new_name", "renamed")),
                "update_fields",
                List.of(explicitNullComment, Map.of("offset", 4, "comment", "note")))));

    DataTypePatch.Struct structPatch =
        assertInstanceOf(DataTypePatch.Struct.class, lastPatch.get());
    assertFalse(structPatch.renameFields().getFirst().commentPresent());
    assertNull(structPatch.renameFields().getFirst().comment());
    assertTrue(structPatch.updateFields().get(0).commentPresent());
    assertNull(structPatch.updateFields().get(0).comment());
    assertTrue(structPatch.updateFields().get(1).commentPresent());
    assertEquals("note", structPatch.updateFields().get(1).comment());

    // Enum patch decodes `comment` and `commentPresent`.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Types/Mode"),
            "patch",
            Map.of(
                "kind",
                "enum",
                "update_values",
                List.of(
                    Map.of("name", "READ", "value", 1),
                    Map.of("name", "WRITE", "comment", "writable")))));
    DataTypePatch.EnumPatch enumPatch =
        assertInstanceOf(DataTypePatch.EnumPatch.class, lastPatch.get());
    assertFalse(enumPatch.updateValues().get(0).commentPresent());
    assertTrue(enumPatch.updateValues().get(1).commentPresent());
    assertEquals("writable", enumPatch.updateValues().get(1).comment());

    // Typedef patch and upsert decode `base_type`; struct upsert returns HTTP 400.
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector",
            Map.of("path", "/Types/Handle"),
            "patch",
            Map.of("kind", "typedef", "base_type", Map.of("kind", "named", "name", "ulonglong"))));
    DataTypePatch.Typedef typedefPatch =
        assertInstanceOf(DataTypePatch.Typedef.class, lastPatch.get());
    assertEquals(DataTypeReference.named("ulonglong"), typedefPatch.baseType());

    registry.dispatch(
        "data_type.upsert",
        Map.of(
            "resource",
            Map.of(
                "kind",
                "typedef",
                "category_path",
                "/Types",
                "name",
                "Handle",
                "base_type",
                Map.of("kind", "named", "name", "ulonglong"))));
    assertEquals(DataTypeResource.Kind.TYPEDEF, lastCreate.get()[1]);
    assertEquals(DataTypeReference.named("ulonglong"), lastCreate.get()[3]);

    ApiException rejectedStructUpsert =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.upsert",
                    Map.of("resource", Map.of("kind", "struct", "name", "NotAllowed"))));
    assertEquals(400, rejectedStructUpsert.status());
  }

  @Test
  void rejectsOversizedStructSizeAndFieldBoundsAtSchemaBoundary() {
    ApiRegistry registry = registryFor(unused(DataTypeService.class));

    ApiException oversizedCreateSize =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "struct",
                            "name",
                            "TooLarge",
                            "size",
                            ApiSchemaCatalog.MAX_STRUCT_SIZE + 1))));
    assertEquals(400, oversizedCreateSize.status());
    assertEquals("/resource/size", oversizedCreateSize.error().target());

    ApiException oversizedInitialOffset =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "struct",
                            "name",
                            "TooFar",
                            "fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "tail",
                                    "offset",
                                    ApiSchemaCatalog.MAX_STRUCT_SIZE + 1,
                                    "data_type",
                                    Map.of("kind", "named", "name", "byte")))))));
    assertEquals(400, oversizedInitialOffset.status());
    assertEquals("/resource/fields/0/offset", oversizedInitialOffset.error().target());

    ApiException oversizedInitialLength =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "struct",
                            "name",
                            "TooLongField",
                            "fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "slice",
                                    "offset",
                                    0,
                                    "length",
                                    ApiSchemaCatalog.MAX_STRUCT_SIZE + 1,
                                    "data_type",
                                    Map.of("kind", "named", "name", "byte")))))));
    assertEquals(400, oversizedInitialLength.status());
    assertEquals("/resource/fields/0/length", oversizedInitialLength.error().target());

    ApiException oversizedPatchOffset =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/Types/Record"),
                        "patch",
                        Map.of(
                            "kind",
                            "struct",
                            "add_fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "tail",
                                    "offset",
                                    ApiSchemaCatalog.MAX_STRUCT_SIZE + 1,
                                    "data_type",
                                    Map.of("kind", "named", "name", "byte")))))));
    assertEquals(400, oversizedPatchOffset.status());
    assertEquals("/patch/add_fields/0/offset", oversizedPatchOffset.error().target());

    ApiException oversizedPatchLength =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/Types/Record"),
                        "patch",
                        Map.of(
                            "kind",
                            "struct",
                            "update_fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "slice",
                                    "length",
                                    ApiSchemaCatalog.MAX_STRUCT_SIZE + 1))))));
    assertEquals(400, oversizedPatchLength.status());
    assertEquals("/patch/update_fields/0/length", oversizedPatchLength.error().target());
  }

  private static ApiRegistry registryFor(DataTypeService dataTypes) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));
    TransactionRunner transaction =
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
            dataTypes,
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
