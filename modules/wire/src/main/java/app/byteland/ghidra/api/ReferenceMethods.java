package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.flowScope;
import static app.byteland.ghidra.api.ApiRegistry.object;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;

import app.byteland.ghidra.service.listing.FlowOverrideScope;
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
                WireSchema.stringEnum(ApiVocabulary.FROM, "to"),
                ApiVocabulary.SELECTOR,
                ApiSchemaCatalog.flowSelector()));
    registry.scanList(
        "reference.list",
        "List references in address order. Select an anchor, scope, or scan range."
            + " Use next_cursor to get the next page.",
        ApiSchemaCatalog.scanListInput(referenceFilter),
        Set.of(
            ApiVocabulary.FROM,
            "to",
            ApiVocabulary.TYPE,
            ApiVocabulary.SOURCE_TYPE,
            "operand_index",
            "primary",
            "from_function",
            "to_function"),
        List.of(ApiVocabulary.FROM, "to", ApiVocabulary.TYPE, "operand_index"),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          Object rawSelector = filter.get(ApiVocabulary.SELECTOR);
          FlowOverrideScope scope =
              rawSelector instanceof Map<?, ?>
                  ? flowScope(object(filter, ApiVocabulary.SELECTOR), "/filter/selector")
                  : null;
          return registry
              .services()
              .referenceService()
              .listReferences(
                  optionalText(filter, ApiVocabulary.FROM),
                  optionalText(filter, "to"),
                  optionalText(filter, ApiVocabulary.TYPE),
                  optionalText(filter, ApiVocabulary.DIRECTION),
                  scope,
                  addressScan(request),
                  page.limit(),
                  page.cursor());
        });
  }
}
