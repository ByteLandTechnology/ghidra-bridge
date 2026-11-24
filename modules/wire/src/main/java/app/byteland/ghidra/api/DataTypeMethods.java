package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.dataType;
import static app.byteland.ghidra.api.ApiRegistry.dataTypePath;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.functionSignature;
import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.objectAt;
import static app.byteland.ghidra.api.ApiRegistry.optionalInteger;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.resource;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

final class DataTypeMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  DataTypeMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> pathSelector = ApiRegistry.selectorSchema(ApiVocabulary.PATH);
    registry.list(
        "data_type_category.list",
        ApiSchemaCatalog.listInput(
            WireSchema.object(ApiSchemaCatalog.props(ApiVocabulary.PATH, WireSchema.string()))),
        Set.of(ApiVocabulary.PATH, ApiVocabulary.NAME, "category_count", "data_type_count"),
        List.of(ApiVocabulary.PATH),
        (request, page) ->
            registry
                .services()
                .dataTypeService()
                .listCategories(
                    optionalText(filter(request), ApiVocabulary.PATH, "/"),
                    page.limit(),
                    page.cursor()));
    registry.read(
        "data_type.get",
        ApiSchemaCatalog.selectorInput(pathSelector),
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        request ->
            registry
                .services()
                .dataTypeService()
                .getDataType(text(selector(request), ApiVocabulary.PATH)));
    registry.list(
        "data_type.list",
        ApiSchemaCatalog.listInput(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    "query",
                    WireSchema.string(),
                    ApiVocabulary.CATEGORY_PATH,
                    WireSchema.string(),
                    ApiVocabulary.KIND,
                    WireSchema.string()))),
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .dataTypeService()
              .searchDataTypes(
                  optionalText(filter, "query", ""),
                  optionalText(filter, ApiVocabulary.CATEGORY_PATH),
                  optionalText(filter, ApiVocabulary.KIND),
                  page.limit(),
                  page.cursor());
        });
    Map<String, Object> writeInput =
        ApiSchemaCatalog.nonEmptyInput(
            ApiSchemaCatalog.props(
                ApiVocabulary.RESOURCE, ApiSchemaCatalog.dataTypeResourceSchema(),
                "declaration", WireSchema.nonBlankString(),
                ApiVocabulary.CATEGORY_PATH, WireSchema.string()));
    registry.writeResource(
        "data_type.create",
        MethodEffects.mutation(false, false),
        writeInput,
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        request -> {
          String createdPath = createDataType(request);
          return registry.services().dataTypeService().getDataType(createdPath);
        });
    registry.writeResource(
        "data_type.patch",
        MethodEffects.mutation(true, false),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                pathSelector,
                ApiVocabulary.PATCH,
                ApiSchemaCatalog.dataTypePatchSchema()),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        request -> {
          patchDataType(request);
          return registry
              .services()
              .dataTypeService()
              .getDataType(text(selector(request), ApiVocabulary.PATH));
        });
    registry.writeResource(
        "data_type.upsert",
        MethodEffects.mutation(true, true),
        writeInput,
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        request -> {
          String upsertedPath = upsertDataType(request);
          return registry.services().dataTypeService().getDataType(upsertedPath);
        });
    registry.writeResult(
        "data_type.delete",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.selectorOnlyInput(pathSelector),
        ApiSchemaCatalog.DELETED_RECEIPT_SCHEMA,
        request -> {
          if (!registry
              .services()
              .dataTypeService()
              .deleteDataType(text(selector(request), ApiVocabulary.PATH))) {
            throw new ApiException(
                409, "data_type_not_removed", "data type could not be removed", "/selector");
          }
          return Map.of(ApiVocabulary.DELETED, true);
        });
  }

  private String createDataType(Map<String, Object> request) {
    return writeDataType(request, false);
  }

  private String upsertDataType(Map<String, Object> request) {
    return writeDataType(request, true);
  }

  private String writeDataType(Map<String, Object> request, boolean upsert) {
    boolean hasResource = request.containsKey(ApiVocabulary.RESOURCE);
    boolean hasDeclaration = request.containsKey("declaration");
    if (hasResource && hasDeclaration) {
      throw ApiException.badRequest(
          "conflicting_fields", "resource and declaration are mutually exclusive", "/declaration");
    }
    if (!hasResource && !hasDeclaration) {
      throw ApiException.badRequest(
          ApiVocabulary.MISSING_FIELD, "resource or declaration is required", "");
    }
    if (hasDeclaration) {
      String declaration = text(request, "declaration");
      if (declaration.isBlank()) {
        throw ApiException.badRequest(
            ApiVocabulary.INVALID_VALUE, "/declaration must not be blank", "/declaration");
      }
      String categoryPath = optionalText(request, ApiVocabulary.CATEGORY_PATH, "/");
      return upsert
          ? registry
              .services()
              .dataTypeService()
              .upsertDataTypeFromDeclaration(categoryPath, declaration)
          : registry
              .services()
              .dataTypeService()
              .createDataTypeFromDeclaration(categoryPath, declaration);
    }
    if (request.containsKey(ApiVocabulary.CATEGORY_PATH)) {
      throw ApiException.badRequest(
          "conflicting_fields",
          "top-level category_path is only valid with declaration; use resource.category_path",
          "/category_path");
    }
    Map<String, Object> resource = resource(request);
    String path = dataTypePath(resource);
    if (!upsert) {
      try {
        registry.services().dataTypeService().getDataType(path);
        throw new ApiException(409, "data_type_exists", "data type already exists", "/resource");
      } catch (NoSuchElementException ignored) {
      }
      writeDataTypeResource(resource, false);
    } else {
      writeDataTypeResource(resource, true);
    }
    return path;
  }

  private void writeDataTypeResource(Map<String, Object> resource, boolean upsert) {
    String kind = text(resource, ApiVocabulary.KIND);
    FunctionSignature signature = null;
    if (ApiVocabulary.FUNCTION.equals(kind)) {
      signature = functionSignature(resource.get("signature"), "/resource/signature");
    }
    DataTypeReference baseType = dataType(resource.get("base_type"), "/resource/base_type");
    String categoryPath = optionalText(resource, ApiVocabulary.CATEGORY_PATH, "/");
    DataTypeResource.Kind resourceKind =
        DataTypeResource.Kind.valueOf(kind.toUpperCase(java.util.Locale.ROOT));
    String name = text(resource, ApiVocabulary.NAME);
    int size = integer(resource, "size", 0);
    if (upsert) {
      registry
          .services()
          .dataTypeService()
          .upsertDataType(categoryPath, resourceKind, name, baseType, size, signature);
    } else {
      registry
          .services()
          .dataTypeService()
          .createDataType(categoryPath, resourceKind, name, baseType, size, signature);
    }
  }

  private void patchDataType(Map<String, Object> request) {
    String path = text(selector(request), ApiVocabulary.PATH);
    Map<String, Object> patch = patch(request);
    String kind = text(patch, ApiVocabulary.KIND);
    DataTypePatch typedPatch =
        switch (kind) {
          case "struct" ->
              new DataTypePatch.Struct(
                  convertedDataTypeFields(patch.get("add_fields"), "/patch/add_fields"),
                  convertedDataTypeFields(patch.get("rename_fields"), "/patch/rename_fields"),
                  convertedDataTypeFields(patch.get("update_fields"), "/patch/update_fields"),
                  convertedDataTypeFields(patch.get("remove_fields"), "/patch/remove_fields"));
          case "union" ->
              new DataTypePatch.Union(
                  convertedDataTypeFields(patch.get("add_fields"), "/patch/add_fields"),
                  convertedDataTypeFields(patch.get("rename_fields"), "/patch/rename_fields"),
                  convertedDataTypeFields(patch.get("update_fields"), "/patch/update_fields"),
                  convertedDataTypeFields(patch.get("remove_fields"), "/patch/remove_fields"));
          case "enum" ->
              new DataTypePatch.EnumPatch(
                  convertedEnumValues(patch.get("add_values")),
                  convertedEnumValues(patch.get("remove_values")),
                  convertedEnumValues(patch.get("rename_values")),
                  convertedEnumValues(patch.get("update_values")));
          default -> throw new AssertionError(kind);
        };
    registry.services().dataTypeService().patchDataType(path, typedPatch);
  }

  @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
  private List<DataTypePatch.CompositeField> convertedDataTypeFields(Object raw, String target) {
    if (!(raw instanceof List<?> list)) return null;
    List<DataTypePatch.CompositeField> result = new ArrayList<>();
    for (int index = 0; index < list.size(); index++) {
      Map<String, Object> field = objectAt(list.get(index), target + "/" + index);
      result.add(
          new DataTypePatch.CompositeField(
              optionalText(field, ApiVocabulary.NAME),
              optionalText(field, "new_name"),
              optionalInteger(field, "offset"),
              optionalInteger(field, ApiVocabulary.LENGTH),
              dataType(field.get(ApiVocabulary.DATA_TYPE), target + "/" + index + "/data_type")));
    }
    return List.copyOf(result);
  }

  @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
  private List<DataTypePatch.EnumValue> convertedEnumValues(Object raw) {
    if (!(raw instanceof List<?> list)) return null;
    List<DataTypePatch.EnumValue> result = new ArrayList<>();
    for (int index = 0; index < list.size(); index++) {
      Map<String, Object> value = objectAt(list.get(index), "/patch/values/" + index);
      result.add(
          new DataTypePatch.EnumValue(
              optionalText(value, ApiVocabulary.NAME),
              optionalText(value, "new_name"),
              value.get("value") instanceof Number number ? number.longValue() : null));
    }
    return List.copyOf(result);
  }
}
