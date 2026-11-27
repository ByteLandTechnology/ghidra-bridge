package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.adapter.ghidra.address.AddressServiceImpl;
import app.byteland.ghidra.adapter.ghidra.datatype.DataTypeServiceImpl;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.globalvariable.GlobalVariableServiceImpl;
import app.byteland.ghidra.adapter.ghidra.listing.ListingServiceImpl;
import app.byteland.ghidra.adapter.ghidra.program.ProgramServiceImpl;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ProjectionAdapterTest {

  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
  private static final AddressFactory ADDRESS_FACTORY =
      new DefaultAddressFactory(new AddressSpace[] {RAM});

  private static Address addr(long offset) {
    return RAM.getAddress(offset);
  }

  static final class StubScript extends GhidraScript {
    StubScript(Program program) {
      this.currentProgram = program;
    }

    @Override
    protected void run() {}
  }

  @Test
  void functionAdapterSkipsSignatureDemanglingVariablesAndEvaluatesFiltersBeforeProjection() {
    Address entry = addr(0x101000L);
    Address calleeEntry = addr(0x102000L);
    Address callee2Entry = addr(0x103000L);
    AddressSet body = new AddressSet(entry, addr(0x10101fL));

    Function callee = guardedCallee(calleeEntry, "_ZN3foo6calleeEv");
    Function callee2 = guardedCallee(callee2Entry, "_ZN3foo7callee2Ev");

    Function fn =
        proxy(
            Function.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> "_ZN3foo3barEv";
                  case "getBody" -> body;
                  case "isExternal", "isThunk" -> false;
                  case "getCalledFunctions" -> Set.of(callee, callee2);
                  case "getSignature",
                          "getProgram",
                          "getParentNamespace",
                          "getReturnType",
                          "getReturn",
                          "getCallingConventionName",
                          "getParameters",
                          "getLocalVariables",
                          "getComment",
                          "getRepeatableComment",
                          "getTags" ->
                      throw new AssertionError(m.getName() + " must be skipped under projection");
                  default -> defaultValue(m.getReturnType());
                });

    Listing listing =
        proxy(
            Listing.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getFunctionAt" -> fnAt(a[0], entry, fn, calleeEntry, callee, callee2);
                  case "getFunctions" -> iteratorProxy(FunctionIterator.class, List.of(fn));
                  default -> defaultValue(m.getReturnType());
                });

    FunctionManager fnManager =
        proxy(
            FunctionManager.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getFunctionAt" -> fnAt(a[0], entry, fn, calleeEntry, callee, callee2);
                  case "getFunctions" -> iteratorProxy(FunctionIterator.class, List.of(fn));
                  default -> defaultValue(m.getReturnType());
                });

    Program program =
        proxy(
            Program.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddressFactory" -> ADDRESS_FACTORY;
                  case "getListing" -> listing;
                  case "getFunctionManager" -> fnManager;
                  case "getMemory" -> emptyMemory();
                  case "getDataTypeManager" ->
                      proxy(
                          ProgramBasedDataTypeManager.class,
                          (dp, dm, da) -> defaultValue(dm.getReturnType()));
                  default -> defaultValue(m.getReturnType());
                });

    FunctionServiceImpl service =
        new FunctionServiceImpl(
            new GhidraSession(new StubScript(program), new QuerySnapshotCache(), () -> false));

    FunctionResource projected =
        service.getFunction("0x00101000", Set.of(), Set.of("entry", "body.start"));
    assertEquals("ram:00101000", projected.entry());
    assertEquals("ram:00101000", projected.body().start());
    assertNull(projected.body().end());
    assertNull(projected.name());
    assertNull(projected.signature());
    assertNull(projected.demangledName());

    Page<FunctionResource> listed =
        service.listFunctions(
            new FunctionService.FunctionQuery(
                new AddressScanOptions(null, null, 1_000),
                10,
                null,
                "_ZN3foo3barEv",
                null,
                null,
                false,
                false,
                Set.of(),
                Set.of("entry")),
            Set.of("entry"));
    assertEquals(1, listed.items().size());
    assertEquals("ram:00101000", listed.items().getFirst().entry());
    assertNull(listed.items().getFirst().name());

    Page<FunctionCallResource> calleesPage1 =
        service.getCallees("0x00101000", 1, null, Set.of("entry"));
    assertEquals(1, calleesPage1.items().size());
    assertEquals("ram:00102000", calleesPage1.items().getFirst().entry());
    assertNull(calleesPage1.items().getFirst().demangledName());

    Page<FunctionCallResource> calleesPage2 =
        service.getCallees("0x00101000", 1, calleesPage1.nextCursor(), Set.of("entry"));
    assertEquals(1, calleesPage2.items().size());
    assertEquals("ram:00103000", calleesPage2.items().getFirst().entry());
    assertNull(calleesPage2.items().getFirst().demangledName());
  }

  @Test
  void symbolAdapterSkipsDemanglingAndEvaluatesFiltersBeforeProjection() {
    Namespace appNs =
        proxy(
            Namespace.class,
            (p, m, a) -> "getName".equals(m.getName()) ? "app" : defaultValue(m.getReturnType()));
    Symbol matching = symbol(10L, "_ZN3app3runEv", addr(0x101000L), appNs);
    Namespace otherNs =
        proxy(
            Namespace.class,
            (p, m, a) ->
                "getName".equals(m.getName()) ? "other" : defaultValue(m.getReturnType()));
    Symbol nonMatching = symbol(11L, "_ZN5other4skipEv", addr(0x101010L), otherNs);

    SymbolTable symbolTable =
        proxy(
            SymbolTable.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getSymbol" -> ((Long) a[0]) == 10L ? matching : null;
                  case "getSymbolIterator" ->
                      iteratorProxy(SymbolIterator.class, List.of(matching, nonMatching));
                  default -> defaultValue(m.getReturnType());
                });

    Program program =
        proxy(
            Program.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddressFactory" -> ADDRESS_FACTORY;
                  case "getSymbolTable" -> symbolTable;
                  case "getMemory" -> emptyMemory();
                  default -> defaultValue(m.getReturnType());
                });

    SymbolServiceImpl service = new SymbolServiceImpl(new GhidraSession(new StubScript(program)));

    SymbolResource sym = service.getSymbol(10L, Set.of("id", "address"));
    assertEquals("10", sym.id());
    assertEquals("ram:00101000", sym.address());
    assertNull(sym.name());
    assertNull(sym.demangledName());

    Page<SymbolResource> page =
        service.listSymbols(
            new SymbolService.SymbolQuery(
                new AddressScanOptions(null, null, 1_000),
                null,
                null,
                null,
                "app",
                null,
                true,
                10,
                null,
                Set.of("address", "id")),
            Set.of("address", "id"));
    assertEquals(1, page.items().size());
    assertEquals("10", page.items().getFirst().id());
    assertNull(page.items().getFirst().namespace());
    assertNull(page.items().getFirst().demangledName());
  }

  @Test
  void dataTypeAdapterSkipsCompositeFieldsAndEvaluatesSearchFiltersBeforeProjection() {
    CategoryPath rootPath = new CategoryPath("/");
    CategoryPath categoryPath = new CategoryPath("/structs");
    CategoryPath extraCategoryPath = new CategoryPath("/unions");
    Structure bigStruct = guardedStruct("/structs/BigPacket", "BigPacket", categoryPath);
    Structure bigStruct2 = guardedStruct("/structs/BigPacket2", "BigPacket2", categoryPath);

    AtomicBoolean allowCategoryDataTypes = new AtomicBoolean(false);
    Category structsCategory =
        guardedChildCategory(
            categoryPath, allowCategoryDataTypes, new DataType[] {bigStruct2, bigStruct});
    Category unionsCategory =
        guardedChildCategory(extraCategoryPath, allowCategoryDataTypes, new DataType[0]);
    Category rootCategory =
        proxy(
            Category.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getCategoryPath" -> rootPath;
                  case "getCategories" -> new Category[] {unionsCategory, structsCategory};
                  default -> defaultValue(m.getReturnType());
                });

    ProgramBasedDataTypeManager dtm =
        proxy(
            ProgramBasedDataTypeManager.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getDataType" ->
                      "/structs/BigPacket2".equals(a[0]) ? bigStruct2 : bigStruct;
                  case "getCategory" -> {
                    if (rootPath.equals(a[0])) yield rootCategory;
                    if (categoryPath.equals(a[0])) yield structsCategory;
                    if (extraCategoryPath.equals(a[0])) yield unionsCategory;
                    yield null;
                  }
                  case "getAllDataTypes" -> List.<DataType>of(bigStruct2, bigStruct).iterator();
                  default -> defaultValue(m.getReturnType());
                });

    Program program =
        proxy(
            Program.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddressFactory" -> ADDRESS_FACTORY;
                  case "getDataTypeManager" -> dtm;
                  default -> defaultValue(m.getReturnType());
                });

    DataTypeServiceImpl service =
        new DataTypeServiceImpl(
            new GhidraSession(new StubScript(program), new QuerySnapshotCache(), () -> false));

    DataTypeResource detail = service.getDataType("/structs/BigPacket", Set.of("path", "size"));
    assertEquals("/structs/BigPacket", detail.path());
    assertEquals(4096, detail.size());
    assertNull(detail.fields());
    assertNull(detail.description());

    Page<DataTypeCategoryResource> catPage1 =
        service.listCategories("/", 1, null, Set.of("path"));
    assertEquals("/structs", catPage1.items().getFirst().path());
    Page<DataTypeCategoryResource> catPage2 =
        service.listCategories("/", 1, catPage1.nextCursor(), Set.of("path"));
    assertEquals("/unions", catPage2.items().getFirst().path());
    assertNull(catPage2.items().getFirst().name());

    allowCategoryDataTypes.set(true);
    Page<DataTypeResource> matches1 =
        service.searchDataTypes("big", "/structs", "struct", 1, null, Set.of("path"));
    assertEquals("/structs/BigPacket", matches1.items().getFirst().path());
    Page<DataTypeResource> matches2 =
        service.searchDataTypes(
            "big", "/structs", "struct", 1, matches1.nextCursor(), Set.of("path"));
    assertEquals("/structs/BigPacket2", matches2.items().getFirst().path());
    assertNull(matches2.items().getFirst().name());
    assertNull(matches2.items().getFirst().kind());
  }

  @Test
  void listingGlobalVariableAddressAndProgramAdaptersSkipUnrequestedReads() {
    AtomicBoolean allowValueReads = new AtomicBoolean(false);
    DataType intType =
        proxy(
            BuiltInDataType.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getName", "getDisplayName" -> "int";
                  case "getPathName" -> "/int";
                  default -> defaultValue(m.getReturnType());
                });

    Instruction insn =
        proxy(
            Instruction.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddress", "getMinAddress", "getMaxAddress" -> addr(0x101000L);
                  case "getLength" -> 1;
                  case "getMnemonicString" -> "NOP";
                  case "getNumOperands" -> 0;
                  case "getFlowOverride" -> FlowOverride.NONE;
                  case "getFlowType", "getDefaultFlowType" -> RefType.FALL_THROUGH;
                  case "getFallThrough" -> addr(0x101001L);
                  default -> defaultValue(m.getReturnType());
                });

    Data guardedData =
        proxy(
            Data.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddress", "getMinAddress" -> addr(0x200000L);
                  case "getMaxAddress" -> addr(0x200003L);
                  case "getLength" -> 4;
                  case "isDefined" -> true;
                  case "getDataType" -> intType;
                  case "getValue" -> {
                    if (!allowValueReads.get()) {
                      throw new AssertionError("Data.getValue must be skipped");
                    }
                    yield 42;
                  }
                  case "getDefaultValueRepresentation" -> {
                    if (!allowValueReads.get()) {
                      throw new AssertionError(
                          "Data.getDefaultValueRepresentation must be skipped");
                    }
                    yield "2ah";
                  }
                  default -> defaultValue(m.getReturnType());
                });
    Memory forbidBytesMemory =
        proxy(
            Memory.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "isEmpty" -> false;
                  case "getMinAddress" -> addr(0x100000L);
                  case "getMaxAddress" -> addr(0x2fffffL);
                  case "getBytes" ->
                      throw new AssertionError("Memory.getBytes must be skipped when unprojected");
                  default -> defaultValue(m.getReturnType());
                });
    Namespace globalNs =
        proxy(
            Namespace.class,
            (p, m, a) -> "getName".equals(m.getName()) ? "vars" : defaultValue(m.getReturnType()));
    Symbol globalSym =
        proxy(
            Symbol.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getName" -> "g_val";
                  case "getAddress" -> addr(0x200000L);
                  case "getParentNamespace" -> globalNs;
                  case "getSymbolType" -> SymbolType.LABEL;
                  case "getSource" -> SourceType.USER_DEFINED;
                  case "isPrimary" -> true;
                  default -> defaultValue(m.getReturnType());
                });
    SymbolTable symbolTable =
        proxy(
            SymbolTable.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getPrimarySymbol" -> addr(0x200000L).equals(a[0]) ? globalSym : null;
                  case "getSymbols" -> new Symbol[] {globalSym};
                  default -> defaultValue(m.getReturnType());
                });
    Listing listing =
        proxy(
            Listing.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getInstructionAt" -> addr(0x101000L).equals(a[0]) ? insn : null;
                  case "getCodeUnits" ->
                      iteratorProxy(CodeUnitIterator.class, List.of(guardedData));
                  case "getDefinedData" -> iteratorProxy(DataIterator.class, List.of(guardedData));
                  case "getDefinedDataAt" -> addr(0x200000L).equals(a[0]) ? guardedData : null;
                  case "getFunctionContaining" -> null;
                  default -> defaultValue(m.getReturnType());
                });
    Program program =
        proxy(
            Program.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddressFactory" -> ADDRESS_FACTORY;
                  case "getListing" -> listing;
                  case "getMemory" -> forbidBytesMemory;
                  case "getSymbolTable" -> symbolTable;
                  default -> defaultValue(m.getReturnType());
                });
    GhidraSession session = new GhidraSession(new StubScript(program));
    ListingServiceImpl listingService = new ListingServiceImpl(session);

    InstructionResource projectedInsn =
        listingService.getInstruction("0x00101000", Set.of("address", "mnemonic"));
    assertEquals("ram:00101000", projectedInsn.address());
    assertEquals("NOP", projectedInsn.mnemonic());
    assertNull(projectedInsn.bytes());

    // CodeUnitResource never reads value/representation even when only bytes are skipped.
    allowValueReads.set(false);
    Page<CodeUnitResource> projectedCu =
        listingService.listCodeUnits(
            new AddressScanOptions("0x00200000", "0x00200003", 1_000),
            10, "all", null, Set.of("address", "kind"));
    assertEquals(1, projectedCu.items().size());
    assertEquals("ram:00200000", projectedCu.items().getFirst().address());
    assertEquals(CodeUnitResource.Kind.DATA, projectedCu.items().getFirst().kind());
    assertNull(projectedCu.items().getFirst().dataType());
    assertNull(projectedCu.items().getFirst().bytes());

    // GlobalVariableQueries evaluates name/namespace filters and skips value/representation.
    GlobalVariableServiceImpl gvService = new GlobalVariableServiceImpl(session);
    Page<GlobalVariableResource> gvPage =
        gvService.listGlobalVariables(
            new GlobalVariableService.Query(
                new AddressScanOptions(null, null, 1_000),
                "g_val", "vars", true, 10, null, Set.of("address")),
            Set.of("address"));
    assertEquals(1, gvPage.items().size());
    assertEquals("ram:00200000", gvPage.items().getFirst().address());
    assertNull(gvPage.items().getFirst().value());
    assertNull(gvPage.items().getFirst().representation());

    // DataUnitResource still returns value/representation when requested and skips bytes.
    allowValueReads.set(true);
    Page<DataUnitResource> dataPage =
        listingService.listDataUnits(
            new AddressScanOptions("0x00200000", "0x00200003", 1_000),
            10, null, Set.of("address", "value", "representation"));
    assertEquals("42", dataPage.items().getFirst().value());
    assertEquals("2ah", dataPage.items().getFirst().representation());
    assertNull(dataPage.items().getFirst().bytes());

    // AddressServiceImpl skips memory, function, symbol, and code_unit lookups when omitted.
    Program addressGuardedProgram =
        proxy(
            Program.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddressFactory" -> ADDRESS_FACTORY;
                  case "getMemory", "getFunctionManager", "getSymbolTable", "getListing" ->
                      throw new AssertionError(m.getName() + " must be skipped under projection");
                  default -> defaultValue(m.getReturnType());
                });
    AddressServiceImpl addressService =
        new AddressServiceImpl(new GhidraSession(new StubScript(addressGuardedProgram)));
    AddressResource resolved = addressService.resolveAddress("0x00101000", Set.of("address"));
    assertEquals("ram:00101000", resolved.address());
    assertNull(resolved.memoryBlock());
    assertNull(resolved.function());
    assertNull(resolved.symbol());
    assertNull(resolved.codeUnit());

    // ProgramServiceImpl skips functionCount and symbolCount and follows active-program switches.
    AtomicReference<Program> activeProgram =
        new AtomicReference<>(namedGuardedProgram("fast.bin"));
    ProgramServiceImpl programService =
        new ProgramServiceImpl(new GhidraSession(activeProgram::get));
    ProgramResource prog = programService.getProgram(Set.of("name"));
    assertEquals("fast.bin", prog.name());
    assertEquals(0L, prog.functionCount());
    assertEquals(0L, prog.symbolCount());
    activeProgram.set(namedGuardedProgram("switched.bin"));
    assertEquals("switched.bin", programService.getProgram(Set.of("name")).name());
  }

  @Test
  void decompilationServiceAndGuiDocumentSkipUnrequestedCodeTokensAndLines() {
    Address entry = addr(0x101000L);
    Program[] programHolder = new Program[1];
    Function fn =
        proxy(
            Function.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> "main";
                  case "getProgram" -> programHolder[0];
                  default -> defaultValue(m.getReturnType());
                });
    Function guiGuardedFn =
        proxy(
            Function.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> "main";
                  case "getProgram" ->
                      throw new AssertionError("GuiDocument must skip getProgram without lines");
                  default -> defaultValue(m.getReturnType());
                });
    DecompileResults guardedResults =
        new DecompileResults(fn, null, null, null, null, null, null) {
          @Override
          public boolean decompileCompleted() {
            return true;
          }
          @Override
          public DecompiledFunction getDecompiledFunction() {
            throw new AssertionError("getDecompiledFunction must be skipped when c is omitted");
          }
          @Override
          public ClangTokenGroup getCCodeMarkup() {
            throw new AssertionError("getCCodeMarkup must be skipped when tokens/c/lines omitted");
          }
        };
    DecompInterface fakeDecomp =
        new DecompInterface() {
          @Override
          public synchronized boolean setOptions(DecompileOptions xmlOptions) {
            return true;
          }
          @Override
          public synchronized int flushCache() {
            return 0;
          }
          @Override
          public synchronized DecompileResults decompileFunction(
              Function function, int timeoutSecs, TaskMonitor monitor) {
            return guardedResults;
          }
        };
    Listing listing =
        proxy(
            Listing.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getFunctionAt" -> entry.equals(a[0]) ? fn : null;
                  case "getCodeUnitContaining" ->
                      throw new AssertionError("getCodeUnitContaining must be skipped");
                  default -> defaultValue(m.getReturnType());
                });
    FunctionManager fnManager =
        proxy(
            FunctionManager.class,
            (p, m, a) ->
                "getFunctionAt".equals(m.getName()) && entry.equals(a[0])
                    ? fn
                    : defaultValue(m.getReturnType()));
    Program program =
        proxy(
            Program.class,
            (p, m, a) ->
                switch (m.getName()) {
                  case "getAddressFactory" -> ADDRESS_FACTORY;
                  case "getListing" -> listing;
                  case "getFunctionManager" -> fnManager;
                  default -> defaultValue(m.getReturnType());
                });
    programHolder[0] = program;
    DecompilationServiceImpl service =
        new DecompilationServiceImpl(
            new GhidraSession(new StubScript(program)), new LeasePool<>(1, () -> fakeDecomp));

    DecompilationResource doc =
        service.decompileFunction(
            "0x00101000", DecompilationResource.Format.DOCUMENT, 1_000, false,
            Set.of("entry", "completed"));
    assertEquals("ram:00101000", doc.entry());
    assertEquals("", doc.c());
    assertEquals(List.of(), doc.lines());

    DecompilationResource tok =
        service.decompileFunction(
            "0x00101000", DecompilationResource.Format.TOKENS, 1_000, false,
            Set.of("entry", "completed"));
    assertEquals(List.of(), tok.tokens());

    ClangTokenGroup group = new ClangTokenGroup(null);
    group.AddTokenGroup(new ClangSyntaxToken(group, "return 0;"));
    group.AddTokenGroup(new ClangBreak(group, 0));
    GuiDocument rendered = GuiDocument.render(guiGuardedFn, group, true, false);
    assertTrue(rendered.code().contains("return 0;"));
    assertEquals(List.of(), rendered.lines());
  }

  private static Program namedGuardedProgram(String name) {
    return proxy(
        Program.class,
        (p, m, a) ->
            switch (m.getName()) {
              case "getName" -> name;
              case "getFunctionManager", "getSymbolTable" ->
                  throw new AssertionError(m.getName() + " must be skipped under projection");
              default -> defaultValue(m.getReturnType());
            });
  }

  private static Symbol symbol(long id, String name, Address address, Namespace ns) {
    return proxy(
        Symbol.class,
        (p, m, a) ->
            switch (m.getName()) {
              case "getID" -> id;
              case "getName" -> name;
              case "getAddress" -> address;
              case "getParentNamespace" -> ns;
              case "getSymbolType" -> SymbolType.FUNCTION;
              case "getSource" -> SourceType.USER_DEFINED;
              case "isPrimary" -> true;
              case "getProgram" ->
                  throw new AssertionError("CppSymbolNames.demangled must be skipped");
              default -> defaultValue(m.getReturnType());
            });
  }

  private static Memory emptyMemory() {
    return proxy(
        Memory.class,
        (p, m, a) ->
            switch (m.getName()) {
              case "isEmpty" -> false;
              case "getMinAddress" -> addr(0x100000L);
              case "getMaxAddress" -> addr(0x2fffffL);
              default -> defaultValue(m.getReturnType());
            });
  }

  private static Function guardedCallee(Address entry, String name) {
    return proxy(
        Function.class,
        (p, m, a) ->
            switch (m.getName()) {
              case "getEntryPoint" -> entry;
              case "getName" -> name;
              case "getProgram", "getParentNamespace", "getSignature" ->
                  throw new AssertionError(m.getName() + " must be skipped under projection");
              default -> defaultValue(m.getReturnType());
            });
  }

  private static Function fnAt(
      Object target, Address e0, Function f0, Address e1, Function f1, Function f2) {
    if (e0.equals(target)) return f0;
    if (e1.equals(target)) return f1;
    return f2.getEntryPoint().equals(target) ? f2 : null;
  }

  private static Structure guardedStruct(String path, String name, CategoryPath categoryPath) {
    return proxy(
        Structure.class,
        (p, m, a) ->
            switch (m.getName()) {
              case "getPathName" -> path;
              case "getName" -> name;
              case "getCategoryPath" -> categoryPath;
              case "getLength" -> 4096;
              case "isZeroLength" -> false;
              case "getNumComponents", "getComponents", "getComponent", "getDescription" ->
                  throw new AssertionError(
                      m.getName() + " must not be called when fields/description are omitted");
              default -> defaultValue(m.getReturnType());
            });
  }

  private static Category guardedChildCategory(
      CategoryPath path, AtomicBoolean allowDataTypes, DataType[] dataTypes) {
    return proxy(
        Category.class,
        (p, m, a) ->
            switch (m.getName()) {
              case "getCategoryPath" -> path;
              case "getDataTypes" -> {
                if (!allowDataTypes.get()) {
                  throw new AssertionError("getDataTypes must be skipped for category path");
                }
                yield dataTypes;
              }
              case "getName", "getCategories" ->
                  throw new AssertionError(
                      m.getName() + " must be skipped when only category path is projected");
              default -> defaultValue(m.getReturnType());
            });
  }

  private static <I, E> I iteratorProxy(Class<I> iface, List<E> items) {
    Iterator<E> it = items.iterator();
    return proxy(
        iface,
        (p, m, a) ->
            switch (m.getName()) {
              case "hasNext" -> it.hasNext();
              case "next" -> it.next();
              case "iterator" -> it;
              default -> defaultValue(m.getReturnType());
            });
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> iface, java.lang.reflect.InvocationHandler handler) {
    return (T)
        Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[] {iface},
            (p, m, a) -> {
              if (m.getDeclaringClass() == Object.class) {
                return switch (m.getName()) {
                  case "toString" -> iface.getSimpleName() + "Proxy";
                  case "hashCode" -> System.identityHashCode(p);
                  case "equals" -> p == a[0];
                  default -> null;
                };
              }
              return handler.invoke(p, m, a);
            });
  }

  private static Object defaultValue(Class<?> returnType) {
    if (returnType == boolean.class) return false;
    if (returnType == int.class) return 0;
    if (returnType == long.class) return 0L;
    return null;
  }
}
