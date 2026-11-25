package app.byteland.ghidra.service;

import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.search.ByteSearchResult;
import app.byteland.ghidra.service.search.SearchService;
import app.byteland.ghidra.service.search.StringSearchResult;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.util.Objects;

/**
 * Holds domain services for an active Ghidra program session.
 *
 * <p>Close this container to release analysis and decompilation resources.
 */
public record BridgeServices(
    ProgramService programService,
    AddressService addressService,
    CommentService commentService,
    ReferenceService referenceService,
    MemoryService memoryService,
    ListingService listingService,
    FunctionService functionService,
    GlobalVariableService globalVariableService,
    AnalysisService analysisService,
    DecompilationService decompilationService,
    SymbolService symbolService,
    DataTypeService dataTypeService,
    SearchService searchService,
    TransactionRunner transactionRunner,
    String programName)
    implements AutoCloseable {

  private static final SearchService UNCONFIGURED_SEARCH_SERVICE =
      new SearchService() {
        @Override
        public StringSearchResult searchStrings(StringSearchQuery query) {
          throw new UnsupportedOperationException("SearchService is not configured");
        }

        @Override
        public ByteSearchResult searchBytes(ByteSearchQuery query) {
          throw new UnsupportedOperationException("SearchService is not configured");
        }
      };

  public BridgeServices {
    Objects.requireNonNull(programService, "programService");
    Objects.requireNonNull(addressService, "addressService");
    Objects.requireNonNull(commentService, "commentService");
    Objects.requireNonNull(referenceService, "referenceService");
    Objects.requireNonNull(memoryService, "memoryService");
    Objects.requireNonNull(listingService, "listingService");
    Objects.requireNonNull(functionService, "functionService");
    Objects.requireNonNull(globalVariableService, "globalVariableService");
    Objects.requireNonNull(analysisService, "analysisService");
    Objects.requireNonNull(decompilationService, "decompilationService");
    Objects.requireNonNull(symbolService, "symbolService");
    Objects.requireNonNull(dataTypeService, "dataTypeService");
    Objects.requireNonNull(searchService, "searchService");
    Objects.requireNonNull(transactionRunner, "transactionRunner");
    Objects.requireNonNull(programName, "programName");
  }

  public BridgeServices(
      ProgramService programService,
      AddressService addressService,
      CommentService commentService,
      ReferenceService referenceService,
      MemoryService memoryService,
      ListingService listingService,
      FunctionService functionService,
      GlobalVariableService globalVariableService,
      AnalysisService analysisService,
      DecompilationService decompilationService,
      SymbolService symbolService,
      DataTypeService dataTypeService,
      TransactionRunner transactionRunner,
      String programName) {
    this(
        programService,
        addressService,
        commentService,
        referenceService,
        memoryService,
        listingService,
        functionService,
        globalVariableService,
        analysisService,
        decompilationService,
        symbolService,
        dataTypeService,
        UNCONFIGURED_SEARCH_SERVICE,
        transactionRunner,
        programName);
  }

  @Override
  @SuppressWarnings("try")
  public void close() {
    try (decompilationService;
        analysisService) {
    }
  }
}
