package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.object;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.service.reference.ReferenceService;
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
    Map<String, Object> fromRangeSchema =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.START,
                WireSchema.nonBlankString(),
                ApiVocabulary.END,
                WireSchema.nonBlankString()),
            ApiVocabulary.START,
            ApiVocabulary.END);
    Map<String, Object> referenceFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.FROM,
                WireSchema.string(),
                ApiVocabulary.ENTRY,
                WireSchema.nonBlankString(),
                "from_range",
                fromRangeSchema,
                "to",
                WireSchema.string(),
                ApiVocabulary.TYPE,
                WireSchema.string(),
                ApiVocabulary.DIRECTION,
                WireSchema.stringEnum(ApiVocabulary.FROM, "to")),
            ApiVocabulary.DIRECTION);
    registry.list(
        "reference.list",
        "List references from an address, function, or range, or to an address."
            + " Set filter.direction.",
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
                  optionalText(filter, ApiVocabulary.ENTRY),
                  fromRange(filter),
                  optionalText(filter, "to"),
                  optionalText(filter, ApiVocabulary.TYPE),
                  referenceDirection(filter),
                  page.limit(),
                  page.cursor());
        });
  }

  private static ReferenceService.RangeFilter fromRange(Map<String, Object> filter) {
    if (!(filter.get("from_range") instanceof Map<?, ?>)) {
      return null;
    }
    Map<String, Object> range = object(filter, "from_range");
    return new ReferenceService.RangeFilter(
        text(range, ApiVocabulary.START), text(range, ApiVocabulary.END));
  }

  private static String referenceDirection(Map<String, Object> filter) {
    return text(filter, ApiVocabulary.DIRECTION);
  }
}
