package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.decompilation.DecompilerPool;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FunctionLocalVariableMutationsTest {
  @Test
  void commitsUncommittedStackRegisterAndDynamicLocalsOnDemandAndSharesDecompilerPool()
      throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("local-patch-test")) {
      Address helperEntry = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401000L);
      Address sampleEntry = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401020L);

      holder.inTransaction(program -> installSampleFunctions(program, helperEntry, sampleEntry));

      GhidraScript script = createScript(holder.program());
      try (BridgeServices services = GhidraServiceFactory.create(script)) {
        String entry = "0x00401020";

        FunctionResource beforePatch =
            services.functionService().getFunction(entry, Set.of("locals"));
        assertEquals(List.of(), beforePatch.localVariables());

        DecompilationResource defaultDecomp =
            services
                .decompilationService()
                .decompileFunction(entry, DecompilationResource.Format.TEXT, 10_000, false, false);
        assertNull(defaultDecomp.localVariables());

        DecompilationResource withLocals =
            services
                .decompilationService()
                .decompileFunction(entry, DecompilationResource.Format.TEXT, 10_000, false, true);
        assertNotNull(withLocals.localVariables());
        assertFalse(withLocals.localVariables().isEmpty());

        FunctionResource.LocalVariableResource uncommittedStack =
            withLocals.localVariables().stream()
                .filter(v -> serializationOf(v).startsWith("Stack["))
                .findFirst()
                .orElseThrow();
        FunctionResource.LocalVariableResource uncommittedTemp =
            withLocals.localVariables().stream()
                .filter(v -> !serializationOf(v).startsWith("Stack["))
                .findFirst()
                .orElseThrow();

        FunctionResource.LocalVariableResource renamedStack =
            services
                .transactionRunner()
                .run(
                    () ->
                        services
                            .functionService()
                            .patchLocalVariable(entry, uncommittedStack.name(), "slot_value", null));
        assertEquals("slot_value", renamedStack.name());
        assertTrue(serializationOf(renamedStack).startsWith("Stack["));

        FunctionResource afterStackPatch =
            services.functionService().getFunction(entry, Set.of("locals"));
        assertEquals(
            List.of("slot_value"),
            afterStackPatch.localVariables().stream()
                .map(FunctionResource.LocalVariableResource::name)
                .toList());

        FunctionResource.LocalVariableResource patchedTemp =
            services
                .transactionRunner()
                .run(
                    () ->
                        services
                            .functionService()
                            .patchLocalVariable(
                                entry,
                                uncommittedTemp.name(),
                                "first_call",
                                DataTypeReference.named("/uint")));
        assertEquals("first_call", patchedTemp.name());
        assertEquals(DataTypeReference.named("/uint"), patchedTemp.dataType());
        assertFalse(serializationOf(patchedTemp).isBlank());

        DecompilationResource refreshedDoc =
            services
                .decompilationService()
                .decompileFunction(
                    entry, DecompilationResource.Format.DOCUMENT, 10_000, false, true);
        assertTrue(refreshedDoc.c().contains("slot_value"));
        assertTrue(refreshedDoc.c().contains("first_call"));
        assertNotNull(refreshedDoc.localVariables());
        assertTrue(
            refreshedDoc.localVariables().stream().anyMatch(v -> "slot_value".equals(v.name())));
        assertTrue(
            refreshedDoc.localVariables().stream().anyMatch(v -> "first_call".equals(v.name())));
      }
    }
  }

  @Test
  void commitsDynamicHashTemporaryOnRetypeOnlyWithoutReadbackFailure() throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("hash-retype-test")) {
      Address helperEntry = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401000L);
      Address sampleEntry = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401020L);

      holder.inTransaction(program -> installSampleFunctions(program, helperEntry, sampleEntry));

      GhidraScript script = createScript(holder.program());
      try (BridgeServices services = GhidraServiceFactory.create(script)) {
        String entry = "0x00401020";
        DecompilationResource withLocals =
            services
                .decompilationService()
                .decompileFunction(entry, DecompilationResource.Format.TEXT, 10_000, false, true);
        FunctionResource.LocalVariableResource uniqueLocal =
            withLocals.localVariables().stream()
                .filter(v -> serializationOf(v).startsWith("unique:") || serializationOf(v).startsWith("register:"))
                .findFirst()
                .orElseThrow();

        FunctionResource.LocalVariableResource retyped =
            services
                .transactionRunner()
                .run(
                    () ->
                        services
                            .functionService()
                            .patchLocalVariable(
                                entry,
                                uniqueLocal.name(),
                                null,
                                DataTypeReference.named("/uint")));
        assertEquals(DataTypeReference.named("/uint"), retyped.dataType());
        assertFalse(serializationOf(retyped).isBlank());
      }
    }
  }

  @Test
  void retypesCommittedLocalAcrossDistinctCategoriesAndSkipsRedundantTypeCommand()
      throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("category-retype-test")) {
      Address entryAddress =
          holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401000L);
      holder.inTransaction(
          program -> {
            MemoryBlock block =
                program
                    .getMemory()
                    .createInitializedBlock(
                        ".text",
                        entryAddress,
                        new ByteArrayInputStream(new byte[] {(byte) 0xc3}),
                        1,
                        TaskMonitor.DUMMY,
                        false);
            block.setExecute(true);
            scriptDisassemble(program, entryAddress);
            Function fn =
                program
                    .getFunctionManager()
                    .createFunction(
                        "cat_fn",
                        entryAddress,
                        new AddressSet(entryAddress, entryAddress),
                        SourceType.USER_DEFINED);

            DataTypeManager dtm = program.getDataTypeManager();
            StructureDataType catAItem = new StructureDataType(new CategoryPath("/cat_a"), "item", 0);
            catAItem.add(IntegerDataType.dataType, "a", null);
            StructureDataType catBItem = new StructureDataType(new CategoryPath("/cat_b"), "item", 0);
            catBItem.add(UnsignedIntegerDataType.dataType, "b", null);
            var resolvedA = dtm.addDataType(catAItem, DataTypeConflictHandler.REPLACE_HANDLER);
            dtm.addDataType(catBItem, DataTypeConflictHandler.REPLACE_HANDLER);

            VariableStorage stackStorage = new VariableStorage(program, -0x10, 4);
            fn.addLocalVariable(
                new LocalVariableImpl("entry_item", 0, resolvedA, stackStorage, program),
                SourceType.USER_DEFINED);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      FunctionServiceImpl service =
          new FunctionServiceImpl(session, newFailingDecompilerPool(session));

      long modBeforeSame = holder.program().getModificationNumber();
      FunctionResource.LocalVariableResource unchanged =
          session.withTransaction(
              () ->
                  service.patchLocalVariable(
                      "0x00401000",
                      "entry_item",
                      null,
                      DataTypeReference.named("/cat_a/item")));
      long modAfterSame = holder.program().getModificationNumber();
      assertEquals(DataTypeReference.named("/cat_a/item"), unchanged.dataType());
      assertEquals(modBeforeSame, modAfterSame);

      FunctionResource.LocalVariableResource updated =
          session.withTransaction(
              () ->
                  service.patchLocalVariable(
                      "0x00401000",
                      "entry_item",
                      null,
                      DataTypeReference.named("/cat_b/item")));
      long modAfterDistinct = holder.program().getModificationNumber();
      assertEquals(DataTypeReference.named("/cat_b/item"), updated.dataType());
      assertTrue(modAfterDistinct > modAfterSame);

      FunctionResource readback = service.getFunction("0x00401000", Set.of("locals"));
      assertEquals(
          DataTypeReference.named("/cat_b/item"),
          readback.localVariables().getFirst().dataType());
    }
  }

  @Test
  void rejectsAmbiguousHighSymbolNameWithBadRequestAndMissingVariableWithNotFound()
      throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("ambiguous-local-test")) {
      Address entryAddress =
          holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401000L);
      holder.inTransaction(
          program -> {
            MemoryBlock block =
                program
                    .getMemory()
                    .createInitializedBlock(
                        ".text",
                        entryAddress,
                        new ByteArrayInputStream(new byte[] {(byte) 0xc3}),
                        1,
                        TaskMonitor.DUMMY,
                        false);
            block.setExecute(true);
            scriptDisassemble(program, entryAddress);
            program
                .getFunctionManager()
                .createFunction(
                    "ambiguous_fn",
                    entryAddress,
                    new AddressSet(entryAddress, entryAddress),
                    SourceType.USER_DEFINED);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      Function function = holder.program().getFunctionManager().getFunctionAt(entryAddress);
      HighFunction stubHigh = createStubHighFunction(holder.program(), function);
      DecompilerPool stubPool = createPoolWithHighFunction(session, stubHigh);
      FunctionServiceImpl service = new FunctionServiceImpl(session, stubPool);

      IllegalArgumentException ambiguous =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  session.withTransaction(
                      () -> service.patchLocalVariable("0x00401000", "dup_local", "renamed", null)));
      ApiFailures.Failure normalizedAmbiguous = ApiFailures.normalize(ambiguous);
      assertEquals(400, normalizedAmbiguous.status());
      assertEquals("invalid_request", normalizedAmbiguous.error().code());

      NoSuchElementException parameterMiss =
          assertThrows(
              NoSuchElementException.class,
              () ->
                  session.withTransaction(
                      () -> service.patchLocalVariable("0x00401000", "param_only", "renamed", null)));
      ApiFailures.Failure normalizedParamMiss = ApiFailures.normalize(parameterMiss);
      assertEquals(404, normalizedParamMiss.status());
      assertEquals("resource_not_found", normalizedParamMiss.error().code());

      NoSuchElementException equateMiss =
          assertThrows(
              NoSuchElementException.class,
              () ->
                  session.withTransaction(
                      () -> service.patchLocalVariable("0x00401000", "EQUATE_VAL", "renamed", null)));
      assertEquals(404, ApiFailures.normalize(equateMiss).status());

      NoSuchElementException unknownMiss =
          assertThrows(
              NoSuchElementException.class,
              () ->
                  session.withTransaction(
                      () -> service.patchLocalVariable("0x00401000", "absent", "renamed", null)));
      assertEquals(404, ApiFailures.normalize(unknownMiss).status());
    }
  }

  @Test
  void functionGetAndListDoNotInvokeDecompiler() throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("zero-decompiler-read-test")) {
      Address entryAddress =
          holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x00401000L);
      holder.inTransaction(
          program -> {
            MemoryBlock block =
                program
                    .getMemory()
                    .createInitializedBlock(
                        ".text",
                        entryAddress,
                        new ByteArrayInputStream(new byte[] {(byte) 0xc3}),
                        1,
                        TaskMonitor.DUMMY,
                        false);
            block.setExecute(true);
            scriptDisassemble(program, entryAddress);
            program
                .getFunctionManager()
                .createFunction(
                    "fast_read_fn",
                    entryAddress,
                    new AddressSet(entryAddress, entryAddress),
                    SourceType.USER_DEFINED);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      FunctionServiceImpl service =
          new FunctionServiceImpl(session, newFailingDecompilerPool(session));

      FunctionResource single =
          service.getFunction("0x00401000", Set.of("parameters", "locals"));
      assertEquals("fast_read_fn", single.name());
      assertEquals(List.of(), single.localVariables());

      var page =
          service.listFunctions(
              new FunctionService.FunctionQuery(
                  AddressScanOptions.of(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS),
                  10,
                  null,
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of("parameters", "locals")));
      assertEquals(1, page.items().size());
      assertEquals(List.of(), page.items().getFirst().localVariables());
    }
  }

  private static void installSampleFunctions(
      ProgramDB program, Address helperEntry, Address sampleEntry) throws Exception {
    DataTypeManager dtm = program.getDataTypeManager();
    dtm.addDataType(IntegerDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);
    dtm.addDataType(UnsignedIntegerDataType.dataType, DataTypeConflictHandler.DEFAULT_HANDLER);

    byte[] code = new byte[0x60];
    // helper at +0x00: mov eax, [rcx]; add eax, 1; ret
    code[0] = (byte) 0x8b;
    code[1] = (byte) 0x01;
    code[2] = (byte) 0x83;
    code[3] = (byte) 0xc0;
    code[4] = (byte) 0x01;
    code[5] = (byte) 0xc3;

    byte[] sampleBytes =
        new byte[] {
          0x53,
          0x48, (byte) 0x83, (byte) 0xec, 0x30,
          (byte) 0x83, (byte) 0xc1, 0x05,
          (byte) 0x89, 0x4c, 0x24, 0x28,
          0x48, (byte) 0x8d, 0x4c, 0x24, 0x28,
          (byte) 0xe8, (byte) 0xca, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0x89, (byte) 0xc3,
          0x48, (byte) 0x8d, 0x4c, 0x24, 0x28,
          (byte) 0xe8, (byte) 0xbe, (byte) 0xff, (byte) 0xff, (byte) 0xff,
          (byte) 0x83, (byte) 0xf3, 0x55,
          0x01, (byte) 0xd8,
          0x48, (byte) 0x83, (byte) 0xc4, 0x30,
          0x5b,
          (byte) 0xc3
        };
    System.arraycopy(sampleBytes, 0, code, 0x20, sampleBytes.length);

    MemoryBlock block =
        program
            .getMemory()
            .createInitializedBlock(
                ".text",
                helperEntry,
                new ByteArrayInputStream(code),
                code.length,
                TaskMonitor.DUMMY,
                false);
    block.setExecute(true);
    scriptDisassemble(program, helperEntry);
    scriptDisassemble(program, sampleEntry);

    Function helper =
        program
            .getFunctionManager()
            .createFunction(
                "helper",
                helperEntry,
                new AddressSet(helperEntry, helperEntry.add(5)),
                SourceType.USER_DEFINED);
    helper.replaceParameters(
        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
        true,
        SourceType.USER_DEFINED,
        new ParameterImpl("ptr", dtm.getPointer(IntegerDataType.dataType), program));
    helper.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);

    Function sample =
        program
            .getFunctionManager()
            .createFunction(
                "sample",
                sampleEntry,
                new AddressSet(sampleEntry, sampleEntry.add(sampleBytes.length - 1)),
                SourceType.USER_DEFINED);
    sample.replaceParameters(
        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
        true,
        SourceType.USER_DEFINED,
        new ParameterImpl("input", IntegerDataType.dataType, program));
    sample.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
  }

  private static void scriptDisassemble(Program program, Address address) {
    GhidraScript script = createScript(program);
    assertTrue(script.disassemble(address));
  }

  private static GhidraScript createScript(Program program) {
    return new GhidraScript() {
      {
        set(program, TaskMonitor.DUMMY);
      }

      @Override
      protected void run() {}
    };
  }

  private static String serializationOf(FunctionResource.LocalVariableResource variable) {
    return ((VariableStorageReference.Serialization) variable.storage()).serialization();
  }

  private static DecompilerPool newFailingDecompilerPool(GhidraSession session) throws Exception {
    DecompInterface failing =
        new DecompInterface() {
          @Override
          public synchronized boolean setOptions(DecompileOptions xmlOptions) {
            throw new AssertionError("decompiler must not run during function read or DB patch");
          }

          @Override
          public synchronized DecompileResults decompileFunction(
              Function func, int timeoutSecs, TaskMonitor monitor) {
            throw new AssertionError("decompiler must not run during function read or DB patch");
          }
        };
    return wrapDecompiler(session, failing);
  }

  private static DecompilerPool createPoolWithHighFunction(
      GhidraSession session, HighFunction highFunction) throws Exception {
    DecompInterface fake =
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
              Function func, int timeoutSecs, TaskMonitor monitor) {
            return new DecompileResults(func, null, null, null, null, null, null) {
              @Override
              public boolean decompileCompleted() {
                return true;
              }

              @Override
              public HighFunction getHighFunction() {
                return highFunction;
              }
            };
          }
        };
    return wrapDecompiler(session, fake);
  }

  private static DecompilerPool wrapDecompiler(GhidraSession session, DecompInterface decompiler)
      throws Exception {
    Class<?> leasePoolClass =
        Class.forName("app.byteland.ghidra.adapter.ghidra.decompilation.LeasePool");
    Constructor<?> poolCtor =
        leasePoolClass.getDeclaredConstructor(int.class, java.util.function.Supplier.class);
    poolCtor.setAccessible(true);
    Object leasePool = poolCtor.newInstance(1, (java.util.function.Supplier<Object>) () -> decompiler);
    Constructor<DecompilerPool> decompilerPoolCtor =
        DecompilerPool.class.getDeclaredConstructor(GhidraSession.class, leasePoolClass);
    decompilerPoolCtor.setAccessible(true);
    return decompilerPoolCtor.newInstance(session, leasePool);
  }

  private static HighFunction createStubHighFunction(Program program, Function function)
      throws Exception {
    PcodeDataTypeManager dtm = new PcodeDataTypeManager(program, new IdentityNameTransformer());
    HighFunction highFunction =
        new HighFunction(function, program.getLanguage(), program.getCompilerSpec(), dtm);
    VariableStorage stackA = new VariableStorage(program, -0x08, 4);
    VariableStorage stackB = new VariableStorage(program, -0x10, 4);
    VariableStorage paramStorage = new VariableStorage(program, program.getRegister("EDI"));

    HighSymbol firstDup =
        new HighSymbol(1L, "dup_local", IntegerDataType.dataType, highFunction) {
          @Override
          public VariableStorage getStorage() {
            return stackA;
          }
        };
    HighSymbol secondDup =
        new HighSymbol(2L, "dup_local", IntegerDataType.dataType, highFunction) {
          @Override
          public VariableStorage getStorage() {
            return stackB;
          }
        };
    HighSymbol paramSymbol =
        new HighSymbol(3L, "param_only", IntegerDataType.dataType, highFunction) {
          @Override
          public boolean isParameter() {
            return true;
          }

          @Override
          public VariableStorage getStorage() {
            return paramStorage;
          }
        };
    EquateSymbol equateSymbol =
        new EquateSymbol(
            4L,
            "EQUATE_VAL",
            42L,
            highFunction,
            function.getEntryPoint(),
            0x1234L);

    List<HighSymbol> symbols = List.of(firstDup, secondDup, paramSymbol, equateSymbol);
    LocalSymbolMap symbolMap =
        new LocalSymbolMap(highFunction, program.getAddressFactory().getStackSpace()) {
          @Override
          public Iterator<HighSymbol> getSymbols() {
            return symbols.iterator();
          }
        };
    return new HighFunction(function, program.getLanguage(), program.getCompilerSpec(), dtm) {
      @Override
      public LocalSymbolMap getLocalSymbolMap() {
        return symbolMap;
      }
    };
  }
}
