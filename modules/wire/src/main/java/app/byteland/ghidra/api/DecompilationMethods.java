package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.functionSelector;
import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.selector;

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
    registry.read(
        "decompilation.get",
        "Decompile a function by entry, address, or symbol. Set scan.timeout_ms between 100 and 300000."
            + " The default is 30000 milliseconds; Ghidra rounds up to whole seconds."
            + " Format document returns GUI lines and cursor addresses from one decompilation."
            + " By default, only pre comments and the plate comment at the entry show."
            + " Set include_comments to show all comments and to return repeatable comments;"
            + " then check comments_complete and warnings.",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                ApiSchemaCatalog.functionLookupSelector(),
                "format",
                WireSchema.stringEnum(ApiVocabulary.TEXT, "tokens", "document"),
                "include_comments",
                WireSchema.bool(),
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
            "lines",
            "comments",
            "comments_complete",
            "warnings",
            "elapsed_ms"),
        List.of(ApiVocabulary.ENTRY),
        request ->
            registry
                .services()
                .decompilationService()
                .decompileFunction(
                    functionSelector(selector(request)),
                    switch (optionalText(request, "format", ApiVocabulary.TEXT)) {
                      case "tokens" -> DecompilationResource.Format.TOKENS;
                      case "document" -> DecompilationResource.Format.DOCUMENT;
                      default -> DecompilationResource.Format.TEXT;
                    },
                    integer(request, "timeout_ms", DecompilationService.DEFAULT_TIMEOUT_MS),
                    bool(request, "include_comments").orElse(false)));
  }
}
