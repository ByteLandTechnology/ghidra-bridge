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
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.util.Objects;

/**
 * Holds domain services for an active Ghidra program session.
 *
 * <p>Close this container to release analysis and decompilation resources.
 *
 * @param programService service for program metadata and address spaces
 * @param addressService service for address parsing and resolution
 * @param commentService service for listing comments
 * @param referenceService service for cross-references
 * @param memoryService service for memory blocks, reads, writes, and searches
 * @param listingService service for code units, instructions, and data items
 * @param functionService service for functions, signatures, and variables
 * @param globalVariableService service for global variables
 * @param analysisService service for background analysis tasks
 * @param decompilationService service for function decompilation
 * @param symbolService service for symbols and namespaces
 * @param dataTypeService service for data types and archives
 * @param transactionRunner runner for atomic program transactions
 * @param programName active program name
 */
@SuppressFBWarnings(
    value = "EI_EXPOSE_REP",
    justification = "Container exposes live session-scoped service collaborators by design")
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

  /** Validates non-null service collaborators. */
  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP2",
      justification = "Container stores live session-scoped service collaborators by design")
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

  @Override
  @SuppressWarnings("try")
  public void close() {
    try (decompilationService;
        analysisService) {
    }
  }
}
