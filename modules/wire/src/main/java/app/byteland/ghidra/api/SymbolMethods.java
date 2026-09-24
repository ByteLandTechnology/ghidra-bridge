package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.longId;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.util.List;
import java.util.Map;

final class SymbolMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  SymbolMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> idSelector = ApiRegistry.selectorSchema("id");
    registry.read(
        "symbol.get",
        ApiSchemaCatalog.selectorInput(idSelector),
        ApiSchemaCatalog.symbolFields(),
        List.of("id"),
        request -> registry.services().symbolService().getSymbol(longId(selector(request), "id")));
    Map<String, Object> symbolFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME, WireSchema.string(),
                ApiVocabulary.ADDRESS, WireSchema.string(),
                ApiVocabulary.TYPE, WireSchema.string(),
                ApiVocabulary.NAMESPACE, WireSchema.string(),
                ApiVocabulary.SOURCE_TYPE, WireSchema.string(),
                ApiVocabulary.CASE_SENSITIVE, WireSchema.bool()));
    registry.scanList(
        "symbol.list",
        ApiSchemaCatalog.scanListInput(symbolFilter),
        ApiSchemaCatalog.symbolFields(),
        List.of(ApiVocabulary.ADDRESS, "id"),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .symbolService()
              .listSymbols(
                  new SymbolService.SymbolQuery(
                      addressScan(request, null, null),
                      optionalText(filter, ApiVocabulary.NAME),
                      optionalText(filter, ApiVocabulary.ADDRESS),
                      optionalText(filter, ApiVocabulary.TYPE),
                      optionalText(filter, ApiVocabulary.NAMESPACE),
                      optionalText(filter, ApiVocabulary.SOURCE_TYPE),
                      Boolean.TRUE.equals(bool(filter, ApiVocabulary.CASE_SENSITIVE).orElse(null)),
                      page.limit(),
                      page.cursor()));
        });
    registry.writeResource(
        "symbol.patch",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                idSelector,
                ApiVocabulary.PATCH,
                WireSchema.object(
                    Map.of(ApiVocabulary.NAME, WireSchema.nonBlankString()), ApiVocabulary.NAME)),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        ApiSchemaCatalog.symbolFields(),
        List.of("id"),
        request -> {
          long id = longId(selector(request), "id");
          registry
              .services()
              .symbolService()
              .renameSymbol(id, text(patch(request), ApiVocabulary.NAME));
          return registry.services().symbolService().getSymbol(id);
        });
  }
}
