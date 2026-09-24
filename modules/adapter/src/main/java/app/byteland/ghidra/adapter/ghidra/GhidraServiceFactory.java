package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.adapter.ghidra.address.AddressServiceImpl;
import app.byteland.ghidra.adapter.ghidra.analysis.AnalysisServiceImpl;
import app.byteland.ghidra.adapter.ghidra.comment.CommentServiceImpl;
import app.byteland.ghidra.adapter.ghidra.datatype.DataTypeServiceImpl;
import app.byteland.ghidra.adapter.ghidra.decompilation.DecompilationServiceImpl;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.globalvariable.GlobalVariableServiceImpl;
import app.byteland.ghidra.adapter.ghidra.listing.ListingServiceImpl;
import app.byteland.ghidra.adapter.ghidra.memory.MemoryServiceImpl;
import app.byteland.ghidra.adapter.ghidra.program.ProgramServiceImpl;
import app.byteland.ghidra.adapter.ghidra.reference.ReferenceServiceImpl;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
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
import ghidra.app.script.GhidraScript;
import java.util.Objects;

/**
 * Creates bridge service implementations bound to a Ghidra script session.
 */
public final class GhidraServiceFactory {
  private GhidraServiceFactory() {}

  /**
   * Creates a service bundle for the active script session.
   *
   * @param script running Ghidra script
   * @return bridge services instance
   */
  public static BridgeServices create(GhidraScript script) {
    Objects.requireNonNull(script, "script");
    GhidraSession context = new GhidraSession(script);

    ProgramService programService = new ProgramServiceImpl(context);
    FunctionService functionService = new FunctionServiceImpl(context);
    GlobalVariableService globalVariableService = new GlobalVariableServiceImpl(context);
    MemoryService memoryService = new MemoryServiceImpl(context);
    ListingService listingService = new ListingServiceImpl(context);
    DecompilationService decompilationService = new DecompilationServiceImpl(context);
    AnalysisService analysisService = new AnalysisServiceImpl(context);
    SymbolService symbolService = new SymbolServiceImpl(context);
    ReferenceService referenceService = new ReferenceServiceImpl(context);
    CommentService commentService = new CommentServiceImpl(context);
    AddressService addressService = new AddressServiceImpl(context);
    DataTypeService dataTypeService = new DataTypeServiceImpl(context);

    return new BridgeServices(
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
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            return context.withTransaction(operation::execute);
          }
        },
        context.currentProgram().getName());
  }
}
