package app.byteland.ghidra.adapter.ghidra.search;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.search.ByteSearchResult;
import app.byteland.ghidra.service.search.SearchService;
import app.byteland.ghidra.service.search.StringSearchResult;
import java.util.Objects;

/**
 * Default adapter implementation of {@link SearchService}.
 */
public final class SearchServiceImpl implements SearchService {
  private final StringIndexCache stringIndexCache;
  private final MemoryService memoryService;

  public SearchServiceImpl(
      GhidraSession context, AnalysisService analysisService, MemoryService memoryService) {
    this(new StringIndexCache(context, analysisService), memoryService);
  }

  public SearchServiceImpl(StringIndexCache stringIndexCache, MemoryService memoryService) {
    this.stringIndexCache = Objects.requireNonNull(stringIndexCache, "stringIndexCache");
    this.memoryService = Objects.requireNonNull(memoryService, "memoryService");
  }

  @Override
  public StringSearchResult searchStrings(StringSearchQuery query) {
    return stringIndexCache.search(query);
  }

  @Override
  public ByteSearchResult searchBytes(ByteSearchQuery query) {
    return memoryService.searchBytes(query);
  }
}
