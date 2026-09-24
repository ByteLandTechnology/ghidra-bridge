package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;

import java.util.List;
import java.util.Map;
import java.util.Set;

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
                ApiVocabulary.START, WireSchema.string(),
                ApiVocabulary.END, WireSchema.string(),
                ApiVocabulary.KIND,
                    WireSchema.stringEnum("all", "instruction", ApiVocabulary.DATA)));
    registry.scanList(
        "code_unit.list",
        ApiSchemaCatalog.scanListInput(listingFilter),
        Set.of(
            ApiVocabulary.ADDRESS,
            ApiVocabulary.KIND,
            ApiVocabulary.LENGTH,
            ApiVocabulary.BYTES,
            ApiVocabulary.TEXT,
            "mnemonic",
            "operands",
            ApiVocabulary.DATA_TYPE),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) ->
            registry
                .services()
                .listingService()
                .listCodeUnits(
                    addressScan(request, ApiVocabulary.START, ApiVocabulary.END),
                    page.limit(),
                    optionalText(filter(request), ApiVocabulary.KIND, "all"),
                    "forward",
                    page.cursor()));
    registry.scanList(
        "data_unit.list",
        ApiSchemaCatalog.scanListInput(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    ApiVocabulary.START,
                    WireSchema.string(),
                    ApiVocabulary.END,
                    WireSchema.string()))),
        Set.of(
            ApiVocabulary.ADDRESS,
            ApiVocabulary.LENGTH,
            ApiVocabulary.DATA_TYPE,
            "value",
            "representation",
            ApiVocabulary.BYTES),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) ->
            registry
                .services()
                .listingService()
                .listDataUnits(
                    addressScan(request, ApiVocabulary.START, ApiVocabulary.END),
                    page.limit(),
                    "forward",
                    page.cursor()));
  }
}
