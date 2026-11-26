package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.text;

import java.util.List;
import java.util.Map;
import java.util.Set;

final class ReferenceMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  ReferenceMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> referenceFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.FROM,
                WireSchema.string(),
                "to",
                WireSchema.string(),
                ApiVocabulary.TYPE,
                WireSchema.string(),
                ApiVocabulary.DIRECTION,
                WireSchema.stringEnum(ApiVocabulary.FROM, "to")),
            ApiVocabulary.DIRECTION);
    registry.list(
        "reference.list",
        "List references from or to an address. Set filter.direction.",
        ApiSchemaCatalog.requiredListInput(referenceFilter),
        Set.of(
            ApiVocabulary.FROM,
            "to",
            ApiVocabulary.TYPE,
            ApiVocabulary.SOURCE_TYPE,
            "operand_index",
            "primary"),
        List.of(ApiVocabulary.FROM, "to", ApiVocabulary.TYPE, "operand_index"),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .referenceService()
              .listReferences(
                  optionalText(filter, ApiVocabulary.FROM),
                  optionalText(filter, "to"),
                  optionalText(filter, ApiVocabulary.TYPE),
                  referenceDirection(filter),
                  page.limit(),
                  page.cursor());
        });
  }

  private static String referenceDirection(Map<String, Object> filter) {
    return text(filter, ApiVocabulary.DIRECTION);
  }
}
