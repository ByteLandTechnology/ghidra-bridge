package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.flowScope;
import static app.byteland.ghidra.api.ApiRegistry.object;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.reference.ReferenceService.ReferenceQuery;
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
                ApiVocabulary.SELECTOR,
                ApiSchemaCatalog.flowSelector(),
                ApiVocabulary.FROM,
                WireSchema.string(),
                "to",
                WireSchema.string(),
                ApiVocabulary.TYPE,
                WireSchema.string(),
                ApiVocabulary.DIRECTION,
                WireSchema.stringEnum(ApiVocabulary.FROM, "to")),
            ApiVocabulary.DIRECTION);
    registry.scanList(
        "reference.list",
        "List references from or to an address, function, or range."
            + " Set filter.direction. Use next_cursor to get the next page.",
        ApiSchemaCatalog.requiredScanListInput(referenceFilter),
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
          FlowOverrideScope scope =
              filter.get(ApiVocabulary.SELECTOR) instanceof Map<?, ?>
                  ? flowScope(object(filter, ApiVocabulary.SELECTOR))
                  : null;
          return registry
              .services()
              .referenceService()
              .listReferences(
                  new ReferenceQuery(
                      scope,
                      optionalText(filter, ApiVocabulary.FROM),
                      optionalText(filter, "to"),
                      optionalText(filter, ApiVocabulary.TYPE),
                      referenceDirection(filter),
                      addressScan(request, null, null),
                      page.limit(),
                      page.cursor()));
        });
  }

  private static String referenceDirection(Map<String, Object> filter) {
    return text(filter, ApiVocabulary.DIRECTION);
  }
}
