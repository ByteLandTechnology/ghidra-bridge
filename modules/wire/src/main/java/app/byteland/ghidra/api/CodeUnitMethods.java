package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;

import java.util.List;
import java.util.Map;

final class CodeUnitMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  CodeUnitMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> listingFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.KIND,
                WireSchema.stringEnum("all", "instruction", ApiVocabulary.DATA)));
    registry.scanList(
        "code_unit.list",
        ApiSchemaCatalog.scanListInput(listingFilter),
        ApiSchemaCatalog.codeUnitFields(),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) ->
            registry
                .services()
                .listingService()
                .listCodeUnits(
                    addressScan(request),
                    page.limit(),
                    optionalText(filter(request), ApiVocabulary.KIND, "all"),
                    page.cursor()));
    registry.scanList(
        "data_unit.list",
        ApiSchemaCatalog.scanListInput(WireSchema.object(Map.of())),
        ApiSchemaCatalog.dataUnitFields(),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) ->
            registry
                .services()
                .listingService()
                .listDataUnits(
                    addressScan(request),
                    page.limit(),
                    page.cursor()));
    registry.scanWindow(
        "listing_window.get",
        "Get code units, data units, symbols, functions, comments, and references for one address"
            + " window. Use next_cursor to get the next window.",
        ApiSchemaCatalog.scanWindowInput(listingFilter),
        ApiSchemaCatalog.listingWindowOutputSchema(),
        (request, page) ->
            registry
                .services()
                .listingService()
                .getListingWindow(
                    addressScan(request),
                    page.limit(),
                    optionalText(filter(request), ApiVocabulary.KIND, "all"),
                    page.cursor()));
  }
}
