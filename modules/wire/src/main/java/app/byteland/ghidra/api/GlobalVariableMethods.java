package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.PATCH_DATA_TYPE_TARGET;
import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.dataType;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.resource;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.Mutation;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.Query;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.WriteMode;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class GlobalVariableMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  GlobalVariableMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> addressSelector = ApiRegistry.addressSelector();
    Set<String> globalVariableFields =
        Set.of(
            ApiVocabulary.ADDRESS,
            ApiVocabulary.NAME,
            ApiVocabulary.NAMESPACE,
            ApiVocabulary.DATA_TYPE,
            ApiVocabulary.LENGTH,
            "value",
            "representation",
            ApiVocabulary.SOURCE_TYPE);
    registry.read(
        "global_variable.get",
        "Get the global variable at one address.",
        ApiSchemaCatalog.selectorInput(addressSelector),
        globalVariableFields,
        List.of(ApiVocabulary.ADDRESS),
        (request, projectedFields) -> {
          String address = text(selector(request), ApiVocabulary.ADDRESS);
          return projectedFields == null
              ? registry.services().globalVariableService().getGlobalVariable(address)
              : registry
                  .services()
                  .globalVariableService()
                  .getGlobalVariable(address, projectedFields);
        });
    Map<String, Object> globalVariableFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.string(),
                ApiVocabulary.NAMESPACE, WireSchema.string(),
                ApiVocabulary.CASE_SENSITIVE, WireSchema.bool()));
    registry.scanList(
        "global_variable.list",
        "List global variables in address order. Set a range or time limit if necessary."
            + " Use next_cursor to get the next page.",
        ApiSchemaCatalog.scanListInput(globalVariableFilter),
        globalVariableFields,
        List.of(ApiVocabulary.ADDRESS),
        (request, page, projectedFields) -> {
          Map<String, Object> filter = filter(request);
          Query query =
              new Query(
                  addressScan(request),
                  optionalText(filter, ApiVocabulary.NAME),
                  optionalText(filter, ApiVocabulary.NAMESPACE),
                  Boolean.TRUE.equals(bool(filter, ApiVocabulary.CASE_SENSITIVE).orElse(null)),
                  page.limit(),
                  page.cursor(),
                  projectedFields);
          return projectedFields == null
              ? registry.services().globalVariableService().listGlobalVariables(query)
              : registry
                  .services()
                  .globalVariableService()
                  .listGlobalVariables(query, projectedFields);
        });
    Map<String, Object> globalVariableDefinition =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ADDRESS, WireSchema.nonBlankString(),
                ApiVocabulary.NAME, WireSchema.nonBlankString(),
                ApiVocabulary.DATA_TYPE, WireSchema.dataTypeReference()),
            ApiVocabulary.ADDRESS,
            ApiVocabulary.NAME,
            ApiVocabulary.DATA_TYPE);
    Map<String, Object> globalVariableInput =
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(ApiVocabulary.RESOURCE, globalVariableDefinition),
            ApiVocabulary.RESOURCE);
    registerGlobalVariableWrite(
        "global_variable.create",
        MethodEffects.mutation(false, false),
        "Create typed data and a primary global variable label at an unused address.",
        globalVariableInput,
        globalVariableFields,
        WriteMode.CREATE);
    Map<String, Object> globalVariablePatch =
        ApiSchemaCatalog.nonEmptyObject(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.nonBlankString(),
                ApiVocabulary.DATA_TYPE, WireSchema.dataTypeReference()));
    registry.writeResource(
        "global_variable.patch",
        MethodEffects.mutation(true, true),
        "Change the name or data type of a global variable.",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR, addressSelector, ApiVocabulary.PATCH, globalVariablePatch),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        globalVariableFields,
        List.of(ApiVocabulary.ADDRESS),
        request -> {
          Map<String, Object> patch = patch(request);
          String address = text(selector(request), ApiVocabulary.ADDRESS);
          writeGlobalVariable(
              new Mutation(
                  address,
                  optionalText(patch, ApiVocabulary.NAME),
                  dataType(patch.get(ApiVocabulary.DATA_TYPE), PATCH_DATA_TYPE_TARGET)),
              WriteMode.PATCH);
          return registry.services().globalVariableService().getGlobalVariable(address);
        });
    registerGlobalVariableWrite(
        "global_variable.upsert",
        MethodEffects.mutation(true, true),
        "Create or replace a typed global variable. Keep unrelated code and data.",
        globalVariableInput,
        globalVariableFields,
        WriteMode.UPSERT);
    registry.writeResult(
        "global_variable.delete",
        MethodEffects.mutation(true, true),
        "Delete a global variable definition. Set delete_symbol to delete its primary label.",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR, addressSelector, "delete_symbol", WireSchema.bool()),
            ApiVocabulary.SELECTOR),
        ApiSchemaCatalog.DELETED_RECEIPT_SCHEMA,
        request -> {
          registry
              .services()
              .globalVariableService()
              .deleteGlobalVariable(
                  text(selector(request), ApiVocabulary.ADDRESS),
                  Boolean.TRUE.equals(bool(request, "delete_symbol").orElse(null)));
          return Map.of(ApiVocabulary.DELETED, true);
        });
  }

  private void registerGlobalVariableWrite(
      String name,
      MethodEffects effects,
      String description,
      Map<String, Object> input,
      Set<String> fields,
      WriteMode mode) {
    registry.writeResource(
        name,
        effects,
        description,
        input,
        fields,
        List.of(ApiVocabulary.ADDRESS),
        request -> {
          Map<String, Object> resource = resource(request);
          writeGlobalVariable(globalVariableMutation(resource), mode);
          return registry
              .services()
              .globalVariableService()
              .getGlobalVariable(text(resource, ApiVocabulary.ADDRESS));
        });
  }

  private static Mutation globalVariableMutation(Map<String, Object> value) {
    return new Mutation(
        text(value, ApiVocabulary.ADDRESS),
        text(value, ApiVocabulary.NAME),
        dataType(value.get(ApiVocabulary.DATA_TYPE), "/resource/data_type"));
  }

  private void writeGlobalVariable(Mutation mutation, WriteMode mode) {
    registry.services().globalVariableService().writeGlobalVariable(mutation, mode);
  }
}
