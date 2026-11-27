package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.program.ProgramService.ExportQuery;
import app.byteland.ghidra.service.program.ProgramService.ImportQuery;
import app.byteland.ghidra.service.program.ProgramTextMatcher;
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
    registerImportAndExportMethods();
  }

  private void registerImportAndExportMethods() {
    Map<String, Object> importFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.string(),
                "library", WireSchema.string(),
                "regex", WireSchema.withDefault(WireSchema.bool(), false),
                "name_regex", WireSchema.string(),
                "library_regex", WireSchema.string()));
    registry.list(
        "import.list",
        "List imported symbols and external functions in the active program.",
        ApiSchemaCatalog.listInput(importFilter),
        ApiSchemaCatalog.importFields(),
        List.of(ApiVocabulary.ADDRESS, "library", ApiVocabulary.NAME),
        (request, page) ->
            registry
                .services()
                .programService()
                .listImports(decodeImportQuery(filter(request), page)));

    Map<String, Object> exportFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.string(),
                ApiVocabulary.NAMESPACE, WireSchema.string(),
                "regex", WireSchema.withDefault(WireSchema.bool(), false),
                "name_regex", WireSchema.string(),
                "is_function", WireSchema.bool()));
    registry.list(
        "export.list",
        "List exported entry points in the active program in address order.",
        ApiSchemaCatalog.listInput(exportFilter),
        ApiSchemaCatalog.exportFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.NAME),
        (request, page) ->
            registry
                .services()
                .programService()
                .listExports(decodeExportQuery(filter(request), page)));
    registry.list(
        "entry_point.list",
        "List external entry points in the active program in address order.",
        ApiSchemaCatalog.listInput(exportFilter),
        ApiSchemaCatalog.exportFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.NAME),
        (request, page) ->
            registry
                .services()
                .programService()
                .listEntryPoints(decodeExportQuery(filter(request), page)));
  }

  private static ImportQuery decodeImportQuery(
      Map<String, Object> filter, ApiRegistry.PageRequest page) {
    String name = optionalText(filter, ApiVocabulary.NAME);
    String library = optionalText(filter, "library");
    boolean regex = Boolean.TRUE.equals(bool(filter, "regex").orElse(null));
    String nameRegex = optionalText(filter, "name_regex");
    String libraryRegex = optionalText(filter, "library_regex");
    ProgramTextMatcher.compile(name, regex, nameRegex, ApiVocabulary.NAME);
    ProgramTextMatcher.compile(library, regex, libraryRegex, "library");
    return new ImportQuery(
        name, library, regex, nameRegex, libraryRegex, page.limit(), page.cursor());
  }

  private static ExportQuery decodeExportQuery(
      Map<String, Object> filter, ApiRegistry.PageRequest page) {
    String name = optionalText(filter, ApiVocabulary.NAME);
    String namespace = optionalText(filter, ApiVocabulary.NAMESPACE);
    boolean regex = Boolean.TRUE.equals(bool(filter, "regex").orElse(null));
    String nameRegex = optionalText(filter, "name_regex");
    Boolean isFunction = bool(filter, "is_function").orElse(null);
    ProgramTextMatcher.compile(name, regex, nameRegex, ApiVocabulary.NAME);
    return new ExportQuery(
        name, namespace, regex, nameRegex, isFunction, page.limit(), page.cursor());
  }
}
