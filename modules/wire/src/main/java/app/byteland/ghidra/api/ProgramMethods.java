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
        request -> registry.services().programService().getProgram());
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
        "program.history",
        "Get the transaction undo and redo stacks for the active program.",
        empty,
        ApiSchemaCatalog.programHistoryFields(),
        List.of("can_undo", "can_redo", "undo_list", "redo_list"),
        request -> registry.services().programService().getHistory());
    registry.writeResult(
        "program.undo",
        MethodEffects.mutationWithoutTransaction(false, false),
        "Undo the latest committed transaction in the active program.",
        empty,
        ApiSchemaCatalog.PROGRAM_UNDO_REDO_SCHEMA,
        request -> registry.services().programService().undo());
    registry.writeResult(
        "program.redo",
        MethodEffects.mutationWithoutTransaction(false, false),
        "Redo the latest undone transaction in the active program.",
        empty,
        ApiSchemaCatalog.PROGRAM_UNDO_REDO_SCHEMA,
        request -> registry.services().programService().redo());
    registry.read(
        "program_language.get",
        ApiSchemaCatalog.input(ApiSchemaCatalog.props(ApiVocabulary.FIELDS, fields)),
        Set.of("language_id", "compiler_spec_id", "processor", "endian", "address_size"),
        List.of("language_id"),
        request -> registry.services().programService().getLanguageInfo());
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
        (request, page) ->
            registry.services().programService().getAddressSpaces(page.limit(), page.cursor()));
  }
}
