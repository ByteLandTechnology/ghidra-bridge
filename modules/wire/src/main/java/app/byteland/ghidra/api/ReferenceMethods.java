package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
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
    Map<String, Object> referenceContextFilter =
        ApiSchemaCatalog.nonEmptyObject(
            ApiSchemaCatalog.props(
                "to",
                WireSchema.nonBlankString(),
                ApiVocabulary.ENTRY,
                WireSchema.nonBlankString(),
                "symbol_id",
                WireSchema.nonBlankString(),
                ApiVocabulary.TYPE,
                WireSchema.string()));
    registry.scanList(
        "reference_context.list",
        "List references to a symbol, function entry, or address with caller summaries and call"
            + " sites. Use next_cursor to get the next page.",
        ApiSchemaCatalog.requiredScanListInput(referenceContextFilter),
        ApiSchemaCatalog.referenceContextFields(),
        List.of(ApiVocabulary.FROM, "to", ApiVocabulary.TYPE, ApiVocabulary.OPERAND_INDEX),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          String to = optionalText(filter, "to");
          String entry = optionalText(filter, ApiVocabulary.ENTRY);
          String symbolId = optionalText(filter, "symbol_id");
          if (to == null && entry == null && symbolId == null) {
            throw ApiException.badRequest(
                "missing_target",
                "filter requires at least one of to, entry, or symbol_id",
                "/filter");
          }
          return registry
              .services()
              .referenceService()
              .listReferenceContext(
                  to,
                  entry,
                  symbolId,
                  optionalText(filter, ApiVocabulary.TYPE),
                  addressScan(request),
                  page.limit(),
                  page.cursor());
        });
  }

  private static String referenceDirection(Map<String, Object> filter) {
    return text(filter, ApiVocabulary.DIRECTION);
  }
}
