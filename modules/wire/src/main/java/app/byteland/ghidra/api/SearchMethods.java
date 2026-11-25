package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalInteger;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.stringList;

import app.byteland.ghidra.service.search.ByteSearchResult;
import app.byteland.ghidra.service.search.SearchService;
import app.byteland.ghidra.service.search.SearchService.ByteSearchQuery;
import app.byteland.ghidra.service.search.SearchService.EncodingFilter;
import app.byteland.ghidra.service.search.SearchService.StringSearchQuery;
import app.byteland.ghidra.service.search.StringSearchResult;
import app.byteland.ghidra.service.search.WildcardBytePattern;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

final class SearchMethods implements ApiMethodProvider {
  private static final Set<String> STRING_FIELDS =
      Set.of(
          ApiVocabulary.ADDRESS,
          "value",
          ApiVocabulary.LENGTH,
          ApiVocabulary.ENCODING,
          "defined",
          ApiVocabulary.DATA_TYPE);
  private static final List<String> STRING_IDENTITY = List.of(ApiVocabulary.ADDRESS);

  private final ApiRegistry registry;

  SearchMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    registerStrings();
    registerBytes();
  }

  private void registerStrings() {
    Map<String, Object> stringFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                "query",
                WireSchema.string(),
                "regex",
                WireSchema.nonBlankString(),
                ApiVocabulary.CASE_SENSITIVE,
                WireSchema.bool(),
                ApiVocabulary.ENCODING,
                WireSchema.stringEnum("all", "ascii", "utf16", "utf16be", "utf16le"),
                "defined",
                WireSchema.bool(),
                "min_length",
                WireSchema.integer(1, SearchService.DEFAULT_MAX_STRING_BYTES)));

    Map<String, Object> stringItemSchema =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ADDRESS,
                WireSchema.string(),
                "value",
                WireSchema.string(),
                ApiVocabulary.LENGTH,
                WireSchema.integer(0, Long.MAX_VALUE),
                ApiVocabulary.ENCODING,
                WireSchema.stringEnum("ascii", "utf16be", "utf16le"),
                "defined",
                WireSchema.bool(),
                ApiVocabulary.DATA_TYPE,
                WireSchema.dataTypeReference()),
            ApiVocabulary.ADDRESS);

    Map<String, Object> stringOutputSchema =
        WireSchema.withDefinitions(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    ApiVocabulary.ITEMS,
                    WireSchema.array(stringItemSchema, 0, Integer.MAX_VALUE),
                    ApiVocabulary.NEXT_CURSOR,
                    WireSchema.nonBlankString(),
                    "index_complete",
                    WireSchema.bool(),
                    "total_indexed",
                    WireSchema.integer(0, Integer.MAX_VALUE),
                    "modification_number",
                    WireSchema.integer(Long.MIN_VALUE, Long.MAX_VALUE)),
                ApiVocabulary.ITEMS,
                "index_complete",
                "total_indexed",
                "modification_number"));

    registry.readWith(
        "search.strings",
        "Search cached ASCII and UTF-16 strings by text or regex."
            + " Use next_cursor to get the next page.",
        ApiSchemaCatalog.scanListInput(stringFilter),
        stringOutputSchema,
        STRING_FIELDS,
        STRING_IDENTITY,
        request -> {
          Map<String, Object> filter = filter(request);
          String regex = optionalText(filter, "regex");
          boolean caseSensitive = bool(filter, ApiVocabulary.CASE_SENSITIVE).orElse(false);
          validateRegex(regex, caseSensitive);

          ApiRegistry.PageRequest page = registry.decodePageRequest(request, "search.strings");
          EncodingFilter encoding =
              EncodingFilter.valueOf(
                  optionalText(filter, ApiVocabulary.ENCODING, "all")
                      .toUpperCase(Locale.ROOT));
          StringSearchQuery query =
              new StringSearchQuery(
                  addressScan(request),
                  page.limit(),
                  page.cursor(),
                  optionalText(filter, "query"),
                  regex,
                  encoding,
                  bool(filter, "defined").orElse(null),
                  optionalInteger(filter, "min_length"),
                  caseSensitive);

          StringSearchResult searchResult = registry.services().searchService().searchStrings(query);
          Map<String, Object> body =
              registry.encodePagedList(
                  "search.strings",
                  request,
                  searchResult.page(),
                  page,
                  STRING_FIELDS,
                  STRING_IDENTITY);
          Map<String, Object> response = new LinkedHashMap<>(body);
          response.put("index_complete", searchResult.indexComplete());
          response.put("total_indexed", searchResult.totalIndexed());
          response.put("modification_number", searchResult.modificationNumber());
          return response;
        });
  }

  private void registerBytes() {
    Map<String, Object> byteInput =
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                "patterns",
                WireSchema.array(
                    WireSchema.nonBlankString(), 1, SearchService.MAX_BYTE_PATTERNS),
                "range",
                ApiSchemaCatalog.ADDRESS_RANGE_SCHEMA,
                "timeout_ms",
                ApiSchemaCatalog.scanTimeoutSchema(),
                ApiVocabulary.LIMIT,
                ApiRegistry.limitSchema(),
                ApiVocabulary.CURSOR,
                ApiRegistry.cursorSchema()),
            "patterns");

    Map<String, Object> patternMatchesSchema =
        WireSchema.object(
            ApiSchemaCatalog.props(
                "index",
                WireSchema.integer(0, SearchService.MAX_BYTE_PATTERNS - 1),
                "pattern",
                WireSchema.nonBlankString(),
                "matches",
                WireSchema.array(WireSchema.nonBlankString(), 0, Integer.MAX_VALUE),
                "match_count",
                WireSchema.integer(0, Integer.MAX_VALUE)),
            "index",
            "pattern",
            "matches",
            "match_count");

    Map<String, Object> byteOutput =
        WireSchema.withDefinitions(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    ApiVocabulary.ITEMS,
                    WireSchema.array(patternMatchesSchema, 1, SearchService.MAX_BYTE_PATTERNS),
                    "total_matches",
                    WireSchema.integer(0, Integer.MAX_VALUE),
                    ApiVocabulary.NEXT_CURSOR,
                    WireSchema.nonBlankString(),
                    ApiVocabulary.SCAN,
                    ApiSchemaCatalog.SCAN_PROGRESS_SCHEMA),
                ApiVocabulary.ITEMS,
                "total_matches",
                ApiVocabulary.SCAN));

    registry.readWith(
        "search.bytes",
        "Scan initialized memory blocks for wildcard hex byte patterns."
            + " Use next_cursor to get the next page.",
        byteInput,
        byteOutput,
        Set.of(),
        List.of(),
        request -> {
          List<String> patterns = stringList(request.get("patterns"));
          validatePatterns(patterns);
          ApiRegistry.PageRequest page = registry.decodePageRequest(request, "search.bytes");
          ByteSearchQuery query =
              new ByteSearchQuery(addressScan(request), page.limit(), page.cursor(), patterns);
          ByteSearchResult result = registry.services().searchService().searchBytes(query);

          Map<String, Object> response = new LinkedHashMap<>();
          response.put(ApiVocabulary.ITEMS, WireValues.normalize(result.items()));
          response.put("total_matches", result.totalMatches());
          if (result.nextCursor() != null) {
            response.put(
                ApiVocabulary.NEXT_CURSOR,
                registry.encodeCursorToken("search.bytes", request, page, result.nextCursor()));
          }
          response.put(ApiVocabulary.SCAN, WireValues.normalize(result.scan()));
          return response;
        });
  }

  private static void validateRegex(String regex, boolean caseSensitive) {
    if (regex == null) return;
    int flags = caseSensitive ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    try {
      Pattern.compile(regex, flags);
    } catch (PatternSyntaxException error) {
      ApiException translated =
          ApiException.badRequest(
              "invalid_regex",
              "filter.regex is invalid: " + error.getDescription(),
              "/filter/regex");
      translated.initCause(error);
      throw translated;
    }
  }

  private static void validatePatterns(List<String> patterns) {
    if (patterns == null || patterns.isEmpty()) {
      throw ApiException.badRequest(
          "missing_field", "/patterns is required", "/patterns");
    }
    for (int i = 0; i < patterns.size(); i++) {
      try {
        WildcardBytePattern.parse(i, patterns.get(i));
      } catch (IllegalArgumentException error) {
        ApiException translated =
            ApiException.badRequest(
                "invalid_pattern", error.getMessage(), "/patterns/" + i);
        translated.initCause(error);
        throw translated;
      }
    }
  }
}
