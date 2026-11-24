package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalInteger;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;

import app.byteland.ghidra.service.listing.ListingService;
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
                    addressScan(request),
                    page.limit(),
                    optionalText(filter(request), ApiVocabulary.KIND, "all"),
                    "forward",
                    page.cursor()));
    registry.scanList(
        "data_unit.list",
        ApiSchemaCatalog.scanListInput(WireSchema.object(Map.of())),
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
                    addressScan(request),
                    page.limit(),
                    "forward",
                    page.cursor()));
    Map<String, Object> stringFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                "query",
                WireSchema.string(),
                "regex",
                WireSchema.nonBlankString(),
                ApiVocabulary.CASE_SENSITIVE,
                WireSchema.bool(),
                "min_length",
                WireSchema.integer(1, Integer.MAX_VALUE),
                ApiVocabulary.ENCODING,
                WireSchema.nonBlankString(),
                "include_candidates",
                WireSchema.bool()));
    registry.scanList(
        "string.list",
        "List strings in address order. Filter by text, regex, length, encoding, or candidate"
            + " bytes. Use next_cursor to get the next page.",
        ApiSchemaCatalog.scanListInput(stringFilter),
        Set.of(
            ApiVocabulary.ADDRESS,
            ApiVocabulary.LENGTH,
            "value",
            ApiVocabulary.ENCODING,
            "defined",
            ApiVocabulary.DATA_TYPE),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .listingService()
              .listStrings(
                  new ListingService.StringQuery(
                      addressScan(request),
                      optionalText(filter, "query"),
                      optionalText(filter, "regex"),
                      Boolean.TRUE.equals(bool(filter, ApiVocabulary.CASE_SENSITIVE).orElse(null)),
                      optionalInteger(filter, "min_length"),
                      optionalText(filter, ApiVocabulary.ENCODING),
                      Boolean.TRUE.equals(bool(filter, "include_candidates").orElse(null)),
                      page.limit(),
                      page.cursor()));
        });
  }
}
