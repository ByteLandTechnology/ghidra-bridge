package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FunctionMutationsTest {
  static {
    UniversalIdGenerator.initialize();
  }

  private static final DataTypeReference INT_REF = DataTypeReference.named("/int");
  private static final DataTypeReference LONGLONG_REF = DataTypeReference.named("/longlong");
  private static final DataTypeReference VOID_REF = DataTypeReference.named("/void");
  private static final DataTypeReference BIG_STRUCT_REF = DataTypeReference.named("/big_ret");

  private static final Map<DataTypeReference, DataType> STATIC_TYPES =
      Map.of(
          INT_REF, IntegerDataType.dataType,
          LONGLONG_REF, LongLongDataType.dataType,
          VOID_REF, VoidDataType.dataType);

  @Test
  void updatesDynamicSignatureAndPreservesSignatureSource() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("dynamic_sig_test")) {
      holder.inTransaction(program -> {
        Function function = createTestFunction(program, "dyn_fn", SourceType.IMPORTED);
        GhidraSession session = GhidraTestSupport.sessionFor(program);
        FunctionMutations.ParameterDataTypeResolver resolver = resolverFor(program);

        FunctionMutations.patchFunction(
            session,
            function,
            null,
            null,
            false,
            null,
            null,
            "   ",
            FunctionAttributePatch.empty(),
            resolver);
        assertFalse(function.hasCustomVariableStorage());

        FunctionMutations.patchFunction(
            session,
            function,
            null,
            null,
            false,
            LONGLONG_REF,
            null,
            "__fastcall",
            FunctionAttributePatch.empty(),
            resolver);

        Function updated = program.getFunctionManager().getFunctionAt(function.getEntryPoint());
        assertFalse(updated.hasCustomVariableStorage());
        assertTrue(LongLongDataType.dataType.isEquivalent(updated.getReturnType()));
        assertEquals("__fastcall", updated.getCallingConventionName());
        assertEquals(SourceType.IMPORTED, updated.getSignatureSource());
        assertEquals(
            new VariableStorage(program, program.getLanguage().getRegister("RAX"))
                .getSerializationString(),
            updated.getReturn().getVariableStorage().getSerializationString());
      });
    }
  }

  @Test
  void derivesStorageWhenEnablingCustomStorageOnReturnTypeOrCallingConventionChange() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("derived_sig_test")) {
      holder.inTransaction(program -> {
        Function function = createTestFunction(program, "derived_fn", SourceType.ANALYSIS);
        GhidraSession session = GhidraTestSupport.sessionFor(program);
        FunctionMutations.ParameterDataTypeResolver resolver = resolverFor(program);

        ParameterImpl existingParam =
            new ParameterImpl(
                "first_arg",
                IntegerDataType.dataType,
                VariableStorage.UNASSIGNED_STORAGE,
                program,
                SourceType.USER_DEFINED);
        existingParam.setComment("preserved comment");
        function.updateFunction(
            null,
            null,
            List.of(existingParam),
            FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            false,
            SourceType.ANALYSIS);

        FunctionMutations.patchFunction(
            session,
            function,
            null,
            null,
            false,
            INT_REF,
            null,
            "__fastcall",
            customStoragePatch(true),
            resolver);

        Function updated = program.getFunctionManager().getFunctionAt(function.getEntryPoint());
        assertTrue(updated.hasCustomVariableStorage());
        assertEquals(SourceType.ANALYSIS, updated.getSignatureSource());
        assertTrue(IntegerDataType.dataType.isEquivalent(updated.getReturnType()));
        assertEquals(
            new VariableStorage(program, program.getLanguage().getRegister("EAX"))
                .getSerializationString(),
            updated.getReturn().getVariableStorage().getSerializationString());
        assertEquals(1, updated.getParameterCount());
        assertEquals("first_arg", updated.getParameters()[0].getName());
        assertEquals("preserved comment", updated.getParameters()[0].getComment());
      });
    }
  }

  @Test
  void appliesExplicitReturnStorageOmitsReturnStoragePointerAndResizesAndResetsCustomStorage() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("explicit_sig_test")) {
      holder.inTransaction(program -> {
        StructureDataType bigStruct = new StructureDataType(CategoryPath.ROOT, "big_ret", 24);
        program
            .getDataTypeManager()
            .addDataType(bigStruct, DataTypeConflictHandler.REPLACE_HANDLER);

        Function function = createTestFunction(program, "custom_fn", SourceType.USER_DEFINED);
        GhidraSession session = GhidraTestSupport.sessionFor(program);
        FunctionMutations.ParameterDataTypeResolver resolver = resolverFor(program);

        FunctionParameterMutations.addParameter(
            session, function, 0, "formal_arg", INT_REF, null, resolver);
        function.getParameters()[0].setComment("arg comment");

        FunctionMutations.patchFunction(
            session,
            function,
            null,
            null,
            false,
            BIG_STRUCT_REF,
            null,
            null,
            FunctionAttributePatch.empty(),
            resolver);

        Function withAutoPtr = program.getFunctionManager().getFunctionAt(function.getEntryPoint());
        assertFalse(withAutoPtr.hasCustomVariableStorage());
        assertEquals(2, withAutoPtr.getParameterCount());
        assertEquals(
            AutoParameterType.RETURN_STORAGE_PTR,
            withAutoPtr.getParameters()[0].getAutoParameterType());

        IllegalArgumentException conflict =
            assertThrows(
                IllegalArgumentException.class,
                () ->
                    FunctionMutations.patchFunction(
                        session,
                        withAutoPtr,
                        null,
                        null,
                        false,
                        LONGLONG_REF,
                        VariableStorageReference.register("R12"),
                        null,
                        customStoragePatch(false),
                        resolver));
        assertEquals(
            "explicit storage cannot be combined with hasCustomVariableStorage=false",
            conflict.getMessage());

        FunctionMutations.patchFunction(
            session,
            withAutoPtr,
            null,
            null,
            false,
            LONGLONG_REF,
            VariableStorageReference.register("R12"),
            null,
            FunctionAttributePatch.empty(),
            resolver);

        Function explicitCustom =
            program.getFunctionManager().getFunctionAt(function.getEntryPoint());
        assertTrue(explicitCustom.hasCustomVariableStorage());
        assertEquals(
            new VariableStorage(program, program.getLanguage().getRegister("R12"))
                .getSerializationString(),
            explicitCustom.getReturn().getVariableStorage().getSerializationString());
        assertEquals(1, explicitCustom.getParameterCount());
        assertEquals("formal_arg", explicitCustom.getParameters()[0].getName());
        assertEquals("arg comment", explicitCustom.getParameters()[0].getComment());

        FunctionMutations.patchFunction(
            session,
            explicitCustom,
            null,
            null,
            false,
            INT_REF,
            null,
            null,
            FunctionAttributePatch.empty(),
            resolver);

        Function resizedCustom =
            program.getFunctionManager().getFunctionAt(function.getEntryPoint());
        assertTrue(resizedCustom.hasCustomVariableStorage());
        assertEquals(
            new VariableStorage(program, program.getLanguage().getRegister("R12D"))
                .getSerializationString(),
            resizedCustom.getReturn().getVariableStorage().getSerializationString());

        FunctionMutations.patchFunction(
            session,
            resizedCustom,
            null,
            null,
            false,
            INT_REF,
            null,
            null,
            customStoragePatch(false),
            resolver);

        Function resetDynamic =
            program.getFunctionManager().getFunctionAt(function.getEntryPoint());
        assertFalse(resetDynamic.hasCustomVariableStorage());
        assertEquals(
            new VariableStorage(program, program.getLanguage().getRegister("EAX"))
                .getSerializationString(),
            resetDynamic.getReturn().getVariableStorage().getSerializationString());
      });
    }
  }

  @Test
  void preservesDistinctDynamicFailureMessagesAndCustomDisableValidation() {
    SignatureStub deriveFailureStub = new SignatureStub(false, true, false);
    TransactionExecutionException deriveError =
        assertThrows(
            TransactionExecutionException.class,
            () ->
                FunctionMutations.patchFunction(
                    deriveFailureStub.session,
                    deriveFailureStub.function,
                    null,
                    null,
                    false,
                    INT_REF,
                    null,
                    null,
                    customStoragePatch(true),
                    STATIC_TYPES::get));
    assertEquals(
        "unable to derive function storage: simulated update failure", deriveError.getMessage());

    SignatureStub updateFailureStub = new SignatureStub(false, true, false);
    TransactionExecutionException updateError =
        assertThrows(
            TransactionExecutionException.class,
            () ->
                FunctionMutations.patchFunction(
                    updateFailureStub.session,
                    updateFailureStub.function,
                    null,
                    null,
                    false,
                    INT_REF,
                    null,
                    null,
                    FunctionAttributePatch.empty(),
                    STATIC_TYPES::get));
    assertEquals(
        "unable to update function signature: simulated update failure", updateError.getMessage());

    SignatureStub stuckCustomStub = new SignatureStub(true, false, true);
    IllegalArgumentException disableError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionMutations.patchFunction(
                    stuckCustomStub.session,
                    stuckCustomStub.function,
                    null,
                    null,
                    false,
                    null,
                    null,
                    null,
                    customStoragePatch(false),
                    STATIC_TYPES::get));
    assertEquals("unable to disable custom variable storage", disableError.getMessage());
  }

  private static Function createTestFunction(
      ProgramDB program, String name, SourceType signatureSource) throws Exception {
    Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10000L);
    if (program.getMemory().getBlock(".text") == null) {
      byte[] bytes = new byte[] {(byte) 0x90, (byte) 0xc3};
      program
          .getMemory()
          .createInitializedBlock(
              ".text",
              entry,
              new ByteArrayInputStream(bytes),
              bytes.length,
              TaskMonitor.DUMMY,
              false);
    }
    Function function =
        program
            .getFunctionManager()
            .createFunction(
                name, entry, new AddressSet(entry, entry.add(1)), SourceType.USER_DEFINED);
    function.setSignatureSource(signatureSource);
    return function;
  }

  private static FunctionMutations.ParameterDataTypeResolver resolverFor(Program program) {
    return input -> GhidraDataTypeReferences.resolve(program.getDataTypeManager(), input);
  }

  private static FunctionAttributePatch customStoragePatch(Boolean customStorage) {
    return new FunctionAttributePatch(null, null, null, customStorage, null);
  }

  private static final class SignatureStub {
    private static final Address ENTRY =
        new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0).getAddress(0x200000);

    private final Function function;
    private final GhidraSession session;

    private SignatureStub(
        boolean initialCustomStorage, boolean failUpdate, boolean keepCustomStorage) {
      Language x64 = GhidraTestSupport.x64Language();
      this.function =
          (Function)
              Proxy.newProxyInstance(
                  Function.class.getClassLoader(),
                  new Class<?>[] {Function.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getEntryPoint" -> ENTRY;
                        case "getCallingConventionName" -> "default";
                        case "hasCustomVariableStorage" ->
                            initialCustomStorage || keepCustomStorage;
                        case "getReturnType" -> VoidDataType.dataType;
                        case "getSignatureSource" -> null;
                        case "getParameters" -> new Parameter[0];
                        case "updateFunction" -> {
                          if (failUpdate) {
                            throw new DuplicateNameException("simulated update failure");
                          }
                          yield null;
                        }
                        default ->
                            throw new AssertionError("Unexpected Function." + method.getName());
                      });
      Listing listing =
          (Listing)
              Proxy.newProxyInstance(
                  Listing.class.getClassLoader(),
                  new Class<?>[] {Listing.class},
                  (proxy, method, args) -> {
                    if ("getFunctionAt".equals(method.getName())) {
                      return function;
                    }
                    throw new AssertionError("Unexpected Listing." + method.getName());
                  });
      Program program =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "isClosed" -> false;
                        case "getDataTypeManager" -> null;
                        case "getListing" -> listing;
                        case "getLanguage" -> x64;
                        case "getAddressFactory" -> x64.getAddressFactory();
                        case "getCompilerSpec" -> x64.getDefaultCompilerSpec();
                        default ->
                            throw new AssertionError("Unexpected Program." + method.getName());
                      });
      GhidraScript script =
          new GhidraScript() {
            {
              set(program, TaskMonitor.DUMMY);
            }

            @Override
            protected void run() {}
          };
      this.session = new GhidraSession(script);
    }
  }
}
