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
import static app.byteland.ghidra.api.ApiRegistry.withFilterDefaults;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
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
        DataTypeMethods::normalizeCategoryListRequest,
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
        withFilterDefaults(Map.of("query", "")),
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
    registry.writeResource(
        "data_type.create",
        MethodEffects.mutation(false, false),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.RESOURCE, ApiSchemaCatalog.dataTypeResourceSchema()),
            ApiVocabulary.RESOURCE),
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        request -> {
          createDataType(request);
          return registry.services().dataTypeService().getDataType(dataTypePath(resource(request)));
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
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.RESOURCE, ApiSchemaCatalog.functionDataTypeResourceSchema()),
            ApiVocabulary.RESOURCE),
        ApiSchemaCatalog.dataTypeFields(),
        List.of(ApiVocabulary.PATH),
        request -> {
          upsertFunctionDataType(request);
          return registry.services().dataTypeService().getDataType(dataTypePath(resource(request)));
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

  private void createDataType(Map<String, Object> request) {
    Map<String, Object> resource = resource(request);
    try {
      registry.services().dataTypeService().getDataType(dataTypePath(resource));
      throw new ApiException(409, "data_type_exists", "data type already exists", "/resource");
    } catch (NoSuchElementException ignored) {
    }
    createDataTypeResource(resource);
  }

  private void upsertFunctionDataType(Map<String, Object> request) {
    createDataTypeResource(resource(request));
  }

  private void createDataTypeResource(Map<String, Object> resource) {
    String kind = text(resource, ApiVocabulary.KIND);
    FunctionSignature signature = null;
    if (ApiVocabulary.FUNCTION.equals(kind)) {
      signature = functionSignature(resource.get("signature"), "/resource/signature");
    }
    DataTypeReference baseType = dataType(resource.get("base_type"), "/resource/base_type");
    registry
        .services()
        .dataTypeService()
        .createDataType(
            optionalText(resource, ApiVocabulary.CATEGORY_PATH, "/"),
            DataTypeResource.Kind.valueOf(kind.toUpperCase(java.util.Locale.ROOT)),
            text(resource, ApiVocabulary.NAME),
            baseType,
            integer(resource, "size", 0),
            signature);
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
                  convertedEnumValues(
                      patch.get("add_values"), "/patch/add_values", EnumValueAction.ADD),
                  convertedEnumValues(
                      patch.get("remove_values"), "/patch/remove_values", EnumValueAction.REMOVE),
                  convertedEnumValues(
                      patch.get("rename_values"), "/patch/rename_values", EnumValueAction.RENAME),
                  convertedEnumValues(
                      patch.get("update_values"), "/patch/update_values", EnumValueAction.UPDATE));
          default -> throw new AssertionError(kind);
        };
    registry.services().dataTypeService().patchDataType(path, typedPatch);
  }

  private static Map<String, Object> normalizeCategoryListRequest(Map<String, Object> request) {
    Map<String, Object> normalized = new LinkedHashMap<>(request);
    Map<String, Object> normalizedFilter = new LinkedHashMap<>(filter(request));
    String path = optionalText(normalizedFilter, ApiVocabulary.PATH);
    if (path == null || path.isBlank()) {
      normalizedFilter.put(ApiVocabulary.PATH, "/");
    }
    normalized.put("filter", Collections.unmodifiableMap(normalizedFilter));
    return Collections.unmodifiableMap(normalized);
  }

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

  private List<DataTypePatch.EnumValue> convertedEnumValues(
      Object raw, String target, EnumValueAction action) {
    if (!(raw instanceof List<?> list)) return null;
    List<DataTypePatch.EnumValue> result = new ArrayList<>();
    for (int index = 0; index < list.size(); index++) {
      String itemTarget = target + "/" + index;
      Map<String, Object> value = objectAt(list.get(index), itemTarget);
      String name = optionalText(value, ApiVocabulary.NAME);
      String newName = optionalText(value, "new_name");
      Long numericValue = value.get("value") instanceof Number number ? number.longValue() : null;
      validateEnumValueItem(action, name, newName, numericValue, itemTarget);
      result.add(new DataTypePatch.EnumValue(name, newName, numericValue));
    }
    return List.copyOf(result);
  }

  private static void validateEnumValueItem(
      EnumValueAction action,
      String name,
      String newName,
      Long numericValue,
      String itemTarget) {
    switch (action) {
      case ADD -> {}
      case REMOVE -> {
        if ((name == null || name.isBlank()) && numericValue == null) {
          throw ApiException.badRequest(
              ApiVocabulary.MISSING_FIELD,
              itemTarget + " requires a non-empty \"name\" or \"value\".",
              itemTarget);
        }
      }
      case RENAME -> {
        requireNonBlankEnumField(name, itemTarget + "/name");
        requireNonBlankEnumField(newName, itemTarget + "/new_name");
      }
      case UPDATE -> requireNonBlankEnumField(name, itemTarget + "/name");
    }
  }

  private static void requireNonBlankEnumField(String value, String fieldTarget) {
    if (value == null) {
      throw ApiException.badRequest(
          ApiVocabulary.MISSING_FIELD, fieldTarget + " is required", fieldTarget);
    }
    if (value.isBlank()) {
      throw ApiException.badRequest(
          ApiVocabulary.INVALID_VALUE, fieldTarget + " must not be empty", fieldTarget);
    }
  }

  private enum EnumValueAction {
    ADD,
    REMOVE,
    RENAME,
    UPDATE
  }
}
