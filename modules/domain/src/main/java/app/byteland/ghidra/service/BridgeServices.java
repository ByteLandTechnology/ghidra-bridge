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
import java.util.function.Supplier;

/**
 * Holds domain services for an active Ghidra program session.
 *
 * <p>Close this container to release analysis and decompilation resources.
 *
 * @param programService program metadata service
 * @param addressService address resolution service
 * @param commentService comment query and mutation service
 * @param referenceService cross-reference query service
 * @param memoryService memory block and byte range service
 * @param listingService instruction, data unit, and flow override service
 * @param functionService function query and mutation service
 * @param globalVariableService global variable query and mutation service
 * @param analysisService auto-analysis lifecycle service
 * @param decompilationService function decompilation service
 * @param symbolService symbol query, rename, and demangle service
 * @param dataTypeService data type query and mutation service
 * @param transactionRunner transactional execution wrapper
 * @param programName fallback Ghidra program name
 * @param programNameSupplier supplier for the active Ghidra program name
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
    String programName,
    Supplier<String> programNameSupplier)
    implements AutoCloseable {

  /** Validates that all domain service references and the program name are non-null. */
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
    Objects.requireNonNull(programNameSupplier, "programNameSupplier");
  }

  /**
   * Creates a fixed-program service bundle whose active program name never changes.
   *
   * @param programService program metadata service
   * @param addressService address resolution service
   * @param commentService comment query and mutation service
   * @param referenceService cross-reference query service
   * @param memoryService memory block and byte range service
   * @param listingService instruction, data unit, and flow override service
   * @param functionService function query and mutation service
   * @param globalVariableService global variable query and mutation service
   * @param analysisService auto-analysis lifecycle service
   * @param decompilationService function decompilation service
   * @param symbolService symbol query, rename, and demangle service
   * @param dataTypeService data type query and mutation service
   * @param transactionRunner transactional execution wrapper
   * @param programName active Ghidra program name
   */
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
        transactionRunner,
        programName,
        () -> programName);
  }

  /**
   * Returns the active Ghidra program name, or the fallback program name when none is open.
   *
   * @return active or fallback program name
   */
  public String currentProgramName() {
    String current = programNameSupplier.get();
    return current == null || current.isBlank() ? programName : current;
  }

  @Override
  @SuppressWarnings("try")
  public void close() {
    try (decompilationService;
        analysisService) {
    }
  }
}
