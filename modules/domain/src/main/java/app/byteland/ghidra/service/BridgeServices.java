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
import app.byteland.ghidra.service.symbol.SymbolService;
import java.util.Objects;

/**
 * Holds domain services for an active Ghidra program session.
 *
 * <p>Close this container to release analysis and decompilation resources.
 *
 * @param programService program metadata and save operations
 * @param addressService address parsing and summary lookup operations
 * @param commentService listing comment read and write operations
 * @param referenceService cross-reference query operations
 * @param memoryService memory block and byte range operations
 * @param listingService code unit, instruction, data, and flow override operations
 * @param functionService function query and signature/variable mutation operations
 * @param globalVariableService global variable query and mutation operations
 * @param analysisService background auto-analysis lifecycle operations
 * @param decompilationService function decompilation operations
 * @param symbolService symbol query, rename, and demangle operations
 * @param dataTypeService data type and category operations
 * @param transactionRunner program transaction runner
 * @param programName active Ghidra program name
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
    TransactionRunner transactionRunner,
    String programName)
    implements AutoCloseable {

  /**
   * Validates that every domain service reference and the program name are non-null.
   */
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
    Objects.requireNonNull(transactionRunner, "transactionRunner");
    Objects.requireNonNull(programName, "programName");
  }

  /**
   * Closes the decompilation and analysis services held by this container.
   */
  @Override
  @SuppressWarnings("try")
  public void close() {
    try (decompilationService;
        analysisService) {
    }
  }
}
