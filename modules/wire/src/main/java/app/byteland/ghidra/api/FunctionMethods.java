package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.PATCH_DATA_TYPE_TARGET;
import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.dataType;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.nullableText;
import static app.byteland.ghidra.api.ApiRegistry.optionalInteger;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.requestedIncludes;
import static app.byteland.ghidra.api.ApiRegistry.resource;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.storage;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;

final class FunctionMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  FunctionMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> entrySelector = ApiRegistry.selectorSchema(ApiVocabulary.ENTRY);
    registry.read(
        "function.get",
        ApiSchemaCatalog.selectorInput(entrySelector),
        ApiSchemaCatalog.functionFields(),
        List.of(ApiVocabulary.ENTRY),
        request ->
            registry
                .services()
                .functionService()
                .getFunction(
                    text(selector(request), ApiVocabulary.ENTRY), requestedIncludes(request)));
    Map<String, Object> functionFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME,
                WireSchema.string(),
                ApiVocabulary.ENTRY,
                WireSchema.string(),
                "contains",
                WireSchema.string(),
                "external",
                WireSchema.bool(),
                "thunk",
                WireSchema.bool()));
    registry.scanList(
        "function.list",
        ApiSchemaCatalog.scanListInput(functionFilter),
        ApiSchemaCatalog.functionFields(),
        List.of(ApiVocabulary.ENTRY),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .functionService()
              .listFunctions(
                  new FunctionQuery(
                      addressScan(request, null, null),
                      page.limit(),
                      page.cursor(),
                      optionalText(filter, ApiVocabulary.NAME),
                      optionalText(filter, ApiVocabulary.ENTRY),
                      optionalText(filter, "contains"),
                      bool(filter, "external").orElse(null),
                      bool(filter, "thunk").orElse(null),
                      requestedIncludes(request)));
        });
    registry.writeResource(
        "function.patch",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                entrySelector,
                ApiVocabulary.PATCH,
                ApiSchemaCatalog.functionPatchSchema()),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        ApiSchemaCatalog.functionFields(),
        List.of(ApiVocabulary.ENTRY),
        request -> {
          String entry = text(selector(request), ApiVocabulary.ENTRY);
          patchFunction(request);
          return registry
              .services()
              .functionService()
              .getFunction(entry, Set.of(ApiVocabulary.PARAMETERS, ApiVocabulary.LOCALS));
        });
    registerFunctionVariableMethods(entrySelector);
    registry.list(
        "function_call.list",
        ApiSchemaCatalog.requiredListInput(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    ApiVocabulary.ENTRY, WireSchema.nonBlankString(),
                    ApiVocabulary.DIRECTION, WireSchema.stringEnum("callers", "callees")),
                ApiVocabulary.ENTRY)),
        Set.of(ApiVocabulary.ENTRY, ApiVocabulary.NAME, "call_site", ApiVocabulary.DIRECTION),
        List.of(ApiVocabulary.ENTRY),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          String entry = text(filter, ApiVocabulary.ENTRY);
          return "callers".equals(optionalText(filter, ApiVocabulary.DIRECTION, "callees"))
              ? registry.services().functionService().getCallers(entry, page.limit(), page.cursor())
              : registry
                  .services()
                  .functionService()
                  .getCallees(entry, page.limit(), page.cursor());
        });
  }

  private void registerFunctionVariableMethods(Map<String, Object> entrySelector) {
    Map<String, Object> storage = ApiSchemaCatalog.storageSchema();
    Map<String, Object> parameterSelector =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ENTRY, WireSchema.nonBlankString(),
                ApiVocabulary.ORDINAL, WireSchema.integer(0, Integer.MAX_VALUE)),
            ApiVocabulary.ENTRY,
            ApiVocabulary.ORDINAL);
    Map<String, Object> parameterResource =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ORDINAL, WireSchema.integer(0, Integer.MAX_VALUE),
                ApiVocabulary.NAME, WireSchema.nonBlankString(),
                ApiVocabulary.DATA_TYPE, WireSchema.dataTypeReference(),
                ApiVocabulary.STORAGE, storage),
            ApiVocabulary.ORDINAL,
            ApiVocabulary.NAME,
            ApiVocabulary.DATA_TYPE);
    Set<String> parameterFields =
        Set.of(
            ApiVocabulary.ORDINAL,
            ApiVocabulary.NAME,
            ApiVocabulary.DATA_TYPE,
            ApiVocabulary.STORAGE);
    registry.writeResource(
        "function_parameter.create",
        MethodEffects.mutation(false, false),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR, entrySelector, ApiVocabulary.RESOURCE, parameterResource),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.RESOURCE),
        parameterFields,
        List.of(ApiVocabulary.ORDINAL),
        request -> {
          Map<String, Object> resource = resource(request);
          String entry = text(selector(request), ApiVocabulary.ENTRY);
          int ordinal = integer(resource, ApiVocabulary.ORDINAL, -1);
          registry
              .services()
              .functionService()
              .addParameter(
                  entry,
                  ordinal,
                  text(resource, ApiVocabulary.NAME),
                  dataType(resource.get(ApiVocabulary.DATA_TYPE), "/resource/data_type"),
                  storage(resource.get(ApiVocabulary.STORAGE)));
          return functionParameter(entry, ordinal);
        });

    Map<String, Object> parameterPatch =
        ApiSchemaCatalog.nonEmptyObject(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.nonBlankString(),
                ApiVocabulary.DATA_TYPE, WireSchema.dataTypeReference(),
                ApiVocabulary.STORAGE, storage));
    registry.writeResource(
        "function_parameter.patch",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR, parameterSelector, ApiVocabulary.PATCH, parameterPatch),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        parameterFields,
        List.of(ApiVocabulary.ORDINAL),
        request -> {
          String entry = text(selector(request), ApiVocabulary.ENTRY);
          int ordinal = integer(selector(request), ApiVocabulary.ORDINAL, -1);
          registry
              .services()
              .functionService()
              .patchParameter(
                  entry,
                  ordinal,
                  optionalText(patch(request), ApiVocabulary.NAME),
                  dataType(patch(request).get(ApiVocabulary.DATA_TYPE), PATCH_DATA_TYPE_TARGET),
                  storage(patch(request).get(ApiVocabulary.STORAGE)));
          return functionParameter(entry, ordinal);
        });
    registry.writeResult(
        "function_parameter.delete",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.selectorOnlyInput(parameterSelector),
        ApiSchemaCatalog.DELETED_RECEIPT_SCHEMA,
        request -> {
          registry
              .services()
              .functionService()
              .removeParameter(
                  text(selector(request), ApiVocabulary.ENTRY),
                  integer(selector(request), ApiVocabulary.ORDINAL, -1));
          return Map.of(ApiVocabulary.DELETED, true);
        });

    Map<String, Object> localSelector =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ENTRY, WireSchema.nonBlankString(),
                ApiVocabulary.NAME, WireSchema.nonBlankString()),
            ApiVocabulary.ENTRY,
            ApiVocabulary.NAME);
    Map<String, Object> localPatch =
        ApiSchemaCatalog.nonEmptyObject(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.nonBlankString(),
                ApiVocabulary.DATA_TYPE, WireSchema.dataTypeReference()));
    Set<String> localVariableFields =
        Set.of(ApiVocabulary.NAME, ApiVocabulary.DATA_TYPE, ApiVocabulary.STORAGE);
    registry.writeResource(
        "function_local_variable.patch",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR, localSelector, ApiVocabulary.PATCH, localPatch),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        localVariableFields,
        List.of(ApiVocabulary.NAME),
        request -> {
          String entry = text(selector(request), ApiVocabulary.ENTRY);
          String oldName = text(selector(request), ApiVocabulary.NAME);
          String newName = optionalText(patch(request), ApiVocabulary.NAME);
          registry
              .services()
              .functionService()
              .patchLocalVariable(
                  entry,
                  oldName,
                  newName,
                  dataType(patch(request).get(ApiVocabulary.DATA_TYPE), PATCH_DATA_TYPE_TARGET));
          return functionLocalVariable(entry, newName == null ? oldName : newName);
        });
  }

  private void patchFunction(Map<String, Object> request) {
    String entry = text(selector(request), ApiVocabulary.ENTRY);
    Map<String, Object> patch = patch(request);
    DataTypeReference returnType = dataType(patch.get("return_type"), "/patch/return_type");
    registry
        .services()
        .functionService()
        .patchFunction(
            entry,
            nullableText(patch, ApiVocabulary.NAME),
            nullableText(patch, "comment"),
            patch.containsKey("comment"),
            returnType,
            storage(patch.get("return_storage")),
            optionalText(patch, "calling_convention"),
            new FunctionAttributePatch(
                bool(patch, "is_inline").orElse(null),
                bool(patch, "has_no_return").orElse(null),
                bool(patch, "has_var_args").orElse(null),
                bool(patch, "has_custom_variable_storage").orElse(null),
                optionalInteger(patch, "stack_purge_size")));
  }

  private FunctionResource.ParameterResource functionParameter(String entry, int ordinal) {
    app.byteland.ghidra.service.function.FunctionResource function =
        registry.services().functionService().getFunction(entry, Set.of(ApiVocabulary.PARAMETERS));
    if (function.parameters() != null) {
      for (app.byteland.ghidra.service.function.FunctionResource.ParameterResource parameter :
          function.parameters()) {
        if (parameter.ordinal() == ordinal) return parameter;
      }
    }
    throw new NoSuchElementException("function parameter was not found after mutation");
  }

  private FunctionResource.LocalVariableResource functionLocalVariable(String entry, String name) {
    FunctionResource function =
        registry.services().functionService().getFunction(entry, Set.of(ApiVocabulary.LOCALS));
    if (function.localVariables() != null) {
      for (FunctionResource.LocalVariableResource variable : function.localVariables()) {
        if (name.equals(variable.name())) return variable;
      }
    }
    throw new NoSuchElementException("function local variable was not found after mutation");
  }
}
