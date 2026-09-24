package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class DecompilationMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  DecompilationMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> fields = ApiRegistry.fieldsSchema();
    Map<String, Object> entrySelector = ApiRegistry.selectorSchema(ApiVocabulary.ENTRY);
    registry.read(
        "decompilation.get",
        "Decompile the function at an entry point. Set scan.timeout_ms between 100 and 300000."
            + " The default is 30000 milliseconds. Ghidra rounds the time up to whole seconds.",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                entrySelector,
                "format",
                WireSchema.stringEnum(ApiVocabulary.TEXT, "tokens"),
                "timeout_ms",
                ApiSchemaCatalog.integerWithDefault(
                    DecompilationService.MIN_TIMEOUT_MS,
                    DecompilationService.MAX_TIMEOUT_MS,
                    DecompilationService.DEFAULT_TIMEOUT_MS),
                ApiVocabulary.FIELDS,
                fields),
            ApiVocabulary.SELECTOR),
        Set.of(
            ApiVocabulary.ENTRY,
            ApiVocabulary.NAME,
            "format",
            "completed",
            "c",
            "tokens",
            "warnings",
            "elapsed_ms"),
        List.of(ApiVocabulary.ENTRY),
        request ->
            registry
                .services()
                .decompilationService()
                .decompileFunction(
                    text(selector(request), ApiVocabulary.ENTRY),
                    "tokens".equals(optionalText(request, "format", ApiVocabulary.TEXT))
                        ? DecompilationResource.Format.TOKENS
                        : DecompilationResource.Format.TEXT,
                    integer(request, "timeout_ms", DecompilationService.DEFAULT_TIMEOUT_MS)));
  }
}
