package app.byteland.ghidra.api;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ProgramMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  ProgramMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> empty = ApiSchemaCatalog.input(Map.of());
    Map<String, Object> fields = ApiRegistry.fieldsSchema();
    registry.read(
        "program.get",
        ApiSchemaCatalog.input(ApiSchemaCatalog.props(ApiVocabulary.FIELDS, fields)),
        ApiSchemaCatalog.programFields(),
        List.of(ApiVocabulary.NAME),
        (request, projectedFields) ->
            projectedFields == null
                ? registry.services().programService().getProgram()
                : registry.services().programService().getProgram(projectedFields));
    registry.writeResult(
        "program.save",
        MethodEffects.mutationWithoutTransaction(false, true),
        empty,
        ApiSchemaCatalog.SAVED_RECEIPT_SCHEMA,
        request -> {
          registry.services().programService().saveProgram();
          return Map.of("saved", true);
        });
    registry.read(
        "program_language.get",
        ApiSchemaCatalog.input(ApiSchemaCatalog.props(ApiVocabulary.FIELDS, fields)),
        Set.of("language_id", "compiler_spec_id", "processor", "endian", "address_size"),
        List.of("language_id"),
        (request, projectedFields) ->
            projectedFields == null
                ? registry.services().programService().getLanguageInfo()
                : registry.services().programService().getLanguageInfo(projectedFields));
    registry.list(
        "address_space.list",
        ApiSchemaCatalog.listInput(WireSchema.object(Map.of())),
        Set.of(
            ApiVocabulary.NAME,
            ApiVocabulary.KIND,
            "size",
            "min_address",
            "max_address",
            "default"),
        List.of(ApiVocabulary.NAME),
        (request, page, projectedFields) ->
            projectedFields == null
                ? registry.services().programService().getAddressSpaces(page.limit(), page.cursor())
                : registry
                    .services()
                    .programService()
                    .getAddressSpaces(page.limit(), page.cursor(), projectedFields));
  }
}
