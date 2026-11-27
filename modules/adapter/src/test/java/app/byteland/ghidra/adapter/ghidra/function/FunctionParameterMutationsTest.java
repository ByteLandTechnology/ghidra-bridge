package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FunctionParameterMutationsTest {
  static {
    UniversalIdGenerator.initialize();
  }

  private static final DataTypeReference INT_REF = DataTypeReference.named("/int");
  private static final DataTypeReference LONGLONG_REF = DataTypeReference.named("/longlong");
  private static final DataTypeReference VOID_REF = DataTypeReference.named("/void");
  private static final DataTypeReference FUNC_DEF_REF = DataTypeReference.named("/fn_t");
  private static final DataTypeReference UNKNOWN_REF = DataTypeReference.named("/missing");

  private static final Map<DataTypeReference, DataType> DATA_TYPES =
      Map.of(
          INT_REF, IntegerDataType.dataType,
          LONGLONG_REF, LongLongDataType.dataType,
          VOID_REF, VoidDataType.dataType,
          FUNC_DEF_REF, new FunctionDefinitionDataType("fn_t"));

  @Test
  void addsDynamicStorageParametersAndPreservesUserDefinedSource() {
    Parameter existing =
        stubParameter(
            "first",
            0,
            IntegerDataType.dataType,
            SourceType.ANALYSIS,
            false,
            registerStorage(0, 4));
    Harness harness = new Harness(false, List.of(existing));

    FunctionParameterMutations.addParameter(
        harness.session, harness.function, 0, "inserted", LONGLONG_REF, null, DATA_TYPES::get);

    assertEquals(1, harness.updates.size());
    RecordedUpdate firstUpdate = harness.updates.getFirst();
    assertEquals(FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, firstUpdate.updateType());
    assertNull(firstUpdate.callingConvention());
    assertNull(firstUpdate.returnVar());
    assertEquals(SourceType.USER_DEFINED, firstUpdate.source());
    assertFalse(firstUpdate.force());
    assertEquals(2, firstUpdate.parameters().size());
    Variable inserted = firstUpdate.parameters().get(0);
    assertInstanceOf(ParameterImpl.class, inserted);
    assertEquals("inserted", inserted.getName());
    assertEquals(SourceType.USER_DEFINED, inserted.getSource());
    assertTrue(inserted.getVariableStorage().isUnassignedStorage());
    assertSame(existing, firstUpdate.parameters().get(1));

    FunctionParameterMutations.addParameter(
        harness.session, harness.function, -1, "appended", INT_REF, null, DATA_TYPES::get);

    assertEquals(2, harness.updates.size());
    RecordedUpdate secondUpdate = harness.updates.get(1);
    assertEquals(FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, secondUpdate.updateType());
    assertEquals(
        List.of("inserted", "first", "appended"),
        secondUpdate.parameters().stream().map(Variable::getName).toList());
    assertEquals(3, harness.function.getParameterCount());
  }

  @Test
  void stripsLeadingAutoParametersForDynamicUpdatesAndRejectsPrecedingOrdinals() {
    DataType voidPtr = new PointerDataType(VoidDataType.dataType);
    Parameter autoThis =
        stubParameter("this", 0, voidPtr, SourceType.ANALYSIS, true, registerStorage(16, 8));
    Parameter formalArg =
        stubParameter(
            "arg",
            1,
            IntegerDataType.dataType,
            SourceType.USER_DEFINED,
            false,
            registerStorage(24, 4));
    Harness harness = new Harness(false, List.of(autoThis, formalArg));

    TransactionExecutionException rejected =
        assertThrows(
            TransactionExecutionException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session,
                    harness.function,
                    0,
                    "before_this",
                    INT_REF,
                    null,
                    DATA_TYPES::get));
    assertEquals(
        "unable to add parameter: Parameter may not be inserted before auto-parameter",
        rejected.getMessage());
    assertEquals(500, rejected.status());
    assertEquals("transaction_failed", rejected.code());
    assertTrue(harness.updates.isEmpty());

    FunctionParameterMutations.addParameter(
        harness.session, harness.function, 1, "after_this", LONGLONG_REF, null, DATA_TYPES::get);

    assertEquals(1, harness.updates.size());
    RecordedUpdate update = harness.updates.getFirst();
    assertEquals(FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, update.updateType());
    assertEquals(SourceType.USER_DEFINED, update.source());
    assertEquals(
        List.of("after_this", "arg"), update.parameters().stream().map(Variable::getName).toList());
    assertEquals(3, harness.function.getParameterCount());
    assertEquals("this", harness.function.getParameters()[0].getName());
    assertEquals("after_this", harness.function.getParameters()[1].getName());
    assertEquals("arg", harness.function.getParameters()[2].getName());
  }

  @Test
  void preservesCustomStorageAndInsertsUnassignedParameterWhenStorageIsNull() {
    VariableStorage customRegister = registerStorage(32, 8);
    Parameter existing =
        stubParameter(
            "custom_arg",
            0,
            LongLongDataType.dataType,
            SourceType.USER_DEFINED,
            false,
            customRegister);
    Harness harness = new Harness(true, List.of(existing));

    FunctionParameterMutations.addParameter(
        harness.session, harness.function, 1, "unassigned_arg", INT_REF, null, DATA_TYPES::get);

    assertEquals(1, harness.updates.size());
    RecordedUpdate update = harness.updates.getFirst();
    assertEquals(FunctionUpdateType.CUSTOM_STORAGE, update.updateType());
    assertNull(update.callingConvention());
    assertNull(update.returnVar());
    assertEquals(SourceType.USER_DEFINED, update.source());
    assertFalse(update.force());
    assertEquals(2, update.parameters().size());
    assertSame(existing, update.parameters().get(0));
    assertSame(customRegister, update.parameters().get(0).getVariableStorage());

    Variable added = update.parameters().get(1);
    assertInstanceOf(ParameterImpl.class, added);
    assertEquals("unassigned_arg", added.getName());
    assertEquals(SourceType.USER_DEFINED, added.getSource());
    assertSame(VariableStorage.UNASSIGNED_STORAGE, added.getVariableStorage());
    assertTrue(harness.function.hasCustomVariableStorage());
    assertSame(customRegister, harness.function.getParameters()[0].getVariableStorage());
    assertTrue(harness.function.getParameters()[1].getVariableStorage().isUnassignedStorage());
  }

  @Test
  void rejectsInvalidInputsWithIllegalArgumentException() {
    Harness harness = new Harness(false, List.of());

    IllegalArgumentException nullName =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 0, null, INT_REF, null, DATA_TYPES::get));
    assertEquals(400, ApiFailures.normalize(nullName).status());

    IllegalArgumentException blankName =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 0, "   ", INT_REF, null, DATA_TYPES::get));
    assertEquals("parameter name is required", blankName.getMessage());

    IllegalArgumentException nullType =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 0, "arg", null, null, DATA_TYPES::get));
    assertEquals("dataType is required", nullType.getMessage());

    assertThrows(
        IllegalArgumentException.class,
        () ->
            FunctionParameterMutations.addParameter(
                harness.session, harness.function, 0, "arg", UNKNOWN_REF, null, DATA_TYPES::get));

    assertThrows(
        IllegalArgumentException.class,
        () ->
            FunctionParameterMutations.addParameter(
                harness.session, harness.function, 0, "arg", FUNC_DEF_REF, null, DATA_TYPES::get));

    IllegalArgumentException voidType =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 0, "arg", VOID_REF, null, DATA_TYPES::get));
    assertInstanceOf(InvalidInputException.class, voidType.getCause());
    assertEquals(400, ApiFailures.normalize(voidType).status());

    IllegalArgumentException outOfRange =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 1, "arg", INT_REF, null, DATA_TYPES::get));
    assertEquals("parameter ordinal out of range: 1", outOfRange.getMessage());
    assertTrue(harness.updates.isEmpty());
  }

  @Test
  void propagatesUpdateFunctionCommandFailureAsTransactionExecutionException() {
    Parameter existing =
        stubParameter(
            "dup",
            0,
            IntegerDataType.dataType,
            SourceType.USER_DEFINED,
            false,
            registerStorage(0, 4));
    Harness harness = new Harness(false, List.of(existing));

    TransactionExecutionException error =
        assertThrows(
            TransactionExecutionException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 1, "dup", INT_REF, null, DATA_TYPES::get));
    assertEquals("unable to add parameter: Duplicate parameter name 'dup'", error.getMessage());
    assertEquals(500, error.status());
    assertEquals("transaction_failed", error.code());
  }

  @Test
  void addsExplicitStorageParametersWithReturnParameterSignatureSourceAndCopiedComments()
      throws InvalidInputException {
    Language x64 = GhidraTestSupport.x64Language();
    Program langProgram = Harness.languageProgram(x64);
    VariableStorage eaxStorage = new VariableStorage(langProgram, x64.getRegister("EAX"));
    VariableStorage rcxStorage = new VariableStorage(langProgram, x64.getRegister("RCX"));
    Parameter existing =
        stubParameter(
            "existing", 0, LongLongDataType.dataType, null, false, rcxStorage, "existing note");
    Parameter returnParam = stubReturn(IntegerDataType.dataType, SourceType.IMPORTED, eaxStorage);
    Harness harness = new Harness(false, List.of(existing), returnParam, SourceType.IMPORTED, x64);

    FunctionParameterMutations.addParameter(
        harness.session,
        harness.function,
        -1,
        "custom_tail",
        LONGLONG_REF,
        VariableStorageReference.register("R12"),
        DATA_TYPES::get);

    assertEquals(1, harness.updates.size());
    RecordedUpdate firstUpdate = harness.updates.getFirst();
    assertEquals(FunctionUpdateType.CUSTOM_STORAGE, firstUpdate.updateType());
    assertNull(firstUpdate.callingConvention());
    assertInstanceOf(ReturnParameterImpl.class, firstUpdate.returnVar());
    assertEquals(IntegerDataType.dataType, firstUpdate.returnVar().getDataType());
    assertEquals(
        eaxStorage.getSerializationString(),
        firstUpdate.returnVar().getVariableStorage().getSerializationString());
    assertEquals(SourceType.IMPORTED, firstUpdate.source());
    assertFalse(firstUpdate.force());
    assertEquals(2, firstUpdate.parameters().size());

    Variable copiedExisting = firstUpdate.parameters().get(0);
    assertInstanceOf(ParameterImpl.class, copiedExisting);
    assertEquals("existing", copiedExisting.getName());
    assertEquals(SourceType.USER_DEFINED, copiedExisting.getSource());
    assertEquals("existing note", copiedExisting.getComment());

    Variable addedTail = firstUpdate.parameters().get(1);
    assertInstanceOf(ParameterImpl.class, addedTail);
    assertEquals("custom_tail", addedTail.getName());
    assertEquals(SourceType.USER_DEFINED, addedTail.getSource());
    assertTrue(harness.function.hasCustomVariableStorage());
    String r12Serialization =
        new VariableStorage(langProgram, x64.getRegister("R12")).getSerializationString();
    assertEquals(
        r12Serialization,
        harness.function.getParameters()[1].getVariableStorage().getSerializationString());

    Harness voidHarness =
        new Harness(
            false,
            List.of(),
            stubReturn(VoidDataType.dataType, SourceType.DEFAULT, VariableStorage.VOID_STORAGE),
            null,
            x64);

    FunctionParameterMutations.addParameter(
        voidHarness.session,
        voidHarness.function,
        0,
        "head_arg",
        INT_REF,
        VariableStorageReference.register("EDX"),
        DATA_TYPES::get);

    RecordedUpdate voidUpdate = voidHarness.updates.getFirst();
    assertInstanceOf(ReturnParameterImpl.class, voidUpdate.returnVar());
    assertTrue(voidUpdate.returnVar().getVariableStorage().isVoidStorage());
    assertEquals(SourceType.USER_DEFINED, voidUpdate.source());
  }

  @Test
  void patchesParameterWithExplicitStoragePreservingCommentsAndSignatureSource()
      throws InvalidInputException {
    Language x64 = GhidraTestSupport.x64Language();
    Program langProgram = Harness.languageProgram(x64);
    VariableStorage raxStorage = new VariableStorage(langProgram, x64.getRegister("RAX"));
    VariableStorage ecxStorage = new VariableStorage(langProgram, x64.getRegister("ECX"));
    VariableStorage r8Storage = new VariableStorage(langProgram, x64.getRegister("R8"));
    VariableStorage r12Storage = new VariableStorage(langProgram, x64.getRegister("R12"));

    Parameter first =
        stubParameter(
            "target",
            0,
            IntegerDataType.dataType,
            SourceType.ANALYSIS,
            false,
            ecxStorage,
            "target comment");
    Parameter second =
        stubParameter(
            "neighbor",
            1,
            LongLongDataType.dataType,
            SourceType.IMPORTED,
            false,
            r8Storage,
            "neighbor comment");
    Parameter returnParam = stubReturn(LongLongDataType.dataType, SourceType.ANALYSIS, raxStorage);
    Harness harness =
        new Harness(false, List.of(first, second), returnParam, SourceType.ANALYSIS, x64);

    FunctionParameterMutations.patchParameter(
        harness.session,
        harness.function,
        0,
        "   ",
        LONGLONG_REF,
        VariableStorageReference.serialization(r12Storage.getSerializationString()),
        DATA_TYPES::get);

    assertEquals(1, harness.updates.size());
    RecordedUpdate update = harness.updates.getFirst();
    assertEquals(FunctionUpdateType.CUSTOM_STORAGE, update.updateType());
    assertInstanceOf(ReturnParameterImpl.class, update.returnVar());
    assertEquals(SourceType.ANALYSIS, update.source());
    assertEquals(2, update.parameters().size());

    Variable patched = update.parameters().get(0);
    assertEquals("target", patched.getName());
    assertEquals(LongLongDataType.dataType, patched.getDataType());
    assertEquals("target comment", patched.getComment());
    assertEquals(
        r12Storage.getSerializationString(), patched.getVariableStorage().getSerializationString());

    Variable copiedNeighbor = update.parameters().get(1);
    assertEquals("neighbor", copiedNeighbor.getName());
    assertEquals(SourceType.IMPORTED, copiedNeighbor.getSource());
    assertEquals("neighbor comment", copiedNeighbor.getComment());
    assertEquals(
        r8Storage.getSerializationString(),
        copiedNeighbor.getVariableStorage().getSerializationString());
  }

  @Test
  void validatesExplicitStorageOrderAndPostUpdateChecks() throws InvalidInputException {
    Language x64 = GhidraTestSupport.x64Language();
    VariableStorage ecxStorage =
        new VariableStorage(Harness.languageProgram(x64), x64.getRegister("ECX"));
    Parameter existing =
        stubParameter(
            "arg0", 0, IntegerDataType.dataType, SourceType.USER_DEFINED, false, ecxStorage, null);
    Parameter voidReturn =
        stubReturn(VoidDataType.dataType, SourceType.USER_DEFINED, VariableStorage.VOID_STORAGE);
    Harness harness =
        new Harness(false, List.of(existing), voidReturn, SourceType.USER_DEFINED, x64);
    VariableStorageReference edxRef = VariableStorageReference.register("EDX");

    IllegalArgumentException blankName =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 0, "", INT_REF, edxRef, DATA_TYPES::get));
    assertEquals("parameter name is required", blankName.getMessage());

    IllegalArgumentException nullType =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session, harness.function, 0, "next", null, edxRef, DATA_TYPES::get));
    assertEquals("dataType is required", nullType.getMessage());

    IllegalArgumentException invalidRegisterBeforeOrdinal =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session,
                    harness.function,
                    9,
                    "next",
                    INT_REF,
                    VariableStorageReference.register("UNKNOWN_REG"),
                    DATA_TYPES::get));
    assertEquals(
        "storage.register names an unknown register: UNKNOWN_REG",
        invalidRegisterBeforeOrdinal.getMessage());

    IllegalArgumentException outOfRange =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.addParameter(
                    harness.session,
                    harness.function,
                    9,
                    "next",
                    INT_REF,
                    edxRef,
                    DATA_TYPES::get));
    assertEquals("parameter ordinal out of range: 9", outOfRange.getMessage());

    IllegalArgumentException sizeMismatch =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.patchParameter(
                    harness.session,
                    harness.function,
                    0,
                    "arg0",
                    INT_REF,
                    VariableStorageReference.register("RAX"),
                    DATA_TYPES::get));
    assertEquals(
        "parameter 0 storage size 8 does not match data type int size 4",
        sizeMismatch.getMessage());
    assertTrue(harness.updates.isEmpty());

    harness.keepDynamicOnCustomUpdate = true;
    IllegalArgumentException missingCustomFlag =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionParameterMutations.patchParameter(
                    harness.session,
                    harness.function,
                    0,
                    "arg0",
                    INT_REF,
                    edxRef,
                    DATA_TYPES::get));
    assertEquals(
        "explicit storage requires custom variable storage", missingCustomFlag.getMessage());
  }

  private static Parameter stubReturn(
      DataType dataType, SourceType source, VariableStorage storage) {
    return stubParameter(
        Parameter.RETURN_NAME, Parameter.RETURN_ORIDINAL, dataType, source, false, storage, null);
  }

  private record RecordedUpdate(
      String callingConvention,
      Variable returnVar,
      List<Variable> parameters,
      FunctionUpdateType updateType,
      boolean force,
      SourceType source) {}

  private static final class Harness {
    private static final Address ENTRY =
        new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0).getAddress(0x100000);

    private boolean customStorage;
    private boolean keepDynamicOnCustomUpdate;
    private List<Parameter> parameters;
    private Parameter returnParameter;
    private SourceType signatureSource;
    private final List<RecordedUpdate> updates = new ArrayList<>();
    private final Program program;
    private final Function function;
    private final GhidraSession session;

    private Harness(boolean customStorage, List<Parameter> initialParameters) {
      this(customStorage, initialParameters, null, SourceType.USER_DEFINED, null);
    }

    private Harness(
        boolean customStorage,
        List<Parameter> initialParameters,
        Parameter initialReturnParameter,
        SourceType initialSignatureSource,
        Language language) {
      this.customStorage = customStorage;
      this.parameters = new ArrayList<>(initialParameters);
      this.returnParameter = initialReturnParameter;
      this.signatureSource = initialSignatureSource;
      this.function =
          (Function)
              Proxy.newProxyInstance(
                  Function.class.getClassLoader(),
                  new Class<?>[] {Function.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getEntryPoint" -> ENTRY;
                        case "getParameterCount" -> parameters.size();
                        case "getParameters" -> parameters.toArray(Parameter[]::new);
                        case "hasCustomVariableStorage" -> this.customStorage;
                        case "getReturnType" -> returnParameter.getDataType();
                        case "getReturn" -> returnParameter;
                        case "getSignatureSource" -> this.signatureSource;
                        case "updateFunction" -> {
                          handleUpdateFunction(args);
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
                    if (method.getName().equals("getFunctionAt")) {
                      assertNotNull(args[0]);
                      assertEquals(ENTRY, args[0]);
                      return function;
                    }
                    throw new AssertionError("Unexpected Listing." + method.getName());
                  });
      this.program =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "isClosed" -> false;
                        case "getDataTypeManager" -> null;
                        case "getListing" -> listing;
                        case "getLanguage" -> {
                          assertNotNull(language);
                          yield language;
                        }
                        case "getAddressFactory" -> {
                          assertNotNull(language);
                          yield language.getAddressFactory();
                        }
                        case "getCompilerSpec" -> {
                          assertNotNull(language);
                          yield language.getDefaultCompilerSpec();
                        }
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

    private static Program languageProgram(Language language) {
      return (Program)
          Proxy.newProxyInstance(
              Program.class.getClassLoader(),
              new Class<?>[] {Program.class},
              (proxy, method, args) ->
                  switch (method.getName()) {
                    case "getLanguage" -> language;
                    case "getAddressFactory" -> language.getAddressFactory();
                    case "getCompilerSpec" -> language.getDefaultCompilerSpec();
                    case "getDataTypeManager" -> null;
                    default -> throw new AssertionError("Unexpected Program." + method.getName());
                  });
    }

    @SuppressWarnings("unchecked")
    private void handleUpdateFunction(Object[] args) throws DuplicateNameException {
      String callingConvention = (String) args[0];
      Variable returnVar = (Variable) args[1];
      List<Variable> newParams = List.copyOf((List<? extends Variable>) args[2]);
      FunctionUpdateType updateType = (FunctionUpdateType) args[3];
      boolean force = (Boolean) args[4];
      SourceType source = (SourceType) args[5];

      Set<String> seenNames = new HashSet<>();
      for (Variable variable : newParams) {
        if (!seenNames.add(variable.getName())) {
          throw new DuplicateNameException("Duplicate parameter name '" + variable.getName() + "'");
        }
      }

      updates.add(
          new RecordedUpdate(callingConvention, returnVar, newParams, updateType, force, source));

      boolean useCustom = updateType == FunctionUpdateType.CUSTOM_STORAGE;
      this.customStorage = useCustom && !keepDynamicOnCustomUpdate;
      this.signatureSource = source;
      if (returnVar != null) {
        this.returnParameter =
            stubParameter(
                Parameter.RETURN_NAME,
                Parameter.RETURN_ORIDINAL,
                returnVar.getDataType(),
                returnVar.getSource(),
                false,
                returnVar.getVariableStorage(),
                returnVar.getComment());
      }
      List<Parameter> rebuilt = new ArrayList<>();
      if (!useCustom) {
        for (Parameter existing : parameters) {
          if (existing.isAutoParameter()) {
            rebuilt.add(existing);
          } else {
            break;
          }
        }
      }
      for (Variable variable : newParams) {
        int ordinal = rebuilt.size();
        DataType dt =
            variable instanceof Parameter param && !useCustom
                ? param.getFormalDataType()
                : variable.getDataType();
        VariableStorage storage =
            useCustom
                ? variable.getVariableStorage()
                : registerStorage(ordinal * 8L, dt.getLength());
        rebuilt.add(
            stubParameter(
                variable.getName(),
                ordinal,
                dt,
                variable.getSource(),
                false,
                storage,
                variable.getComment()));
      }
      this.parameters = rebuilt;
    }
  }

  private static VariableStorage registerStorage(long offset, int size) {
    GenericAddressSpace regSpace =
        new GenericAddressSpace("register", 32, GenericAddressSpace.TYPE_REGISTER, 1);
    Varnode varnode = new Varnode(regSpace.getAddress(offset), size);
    return new StubStorage(varnode);
  }

  private static final class StubStorage extends VariableStorage {
    private final Varnode varnode;

    private StubStorage(Varnode varnode) {
      this.varnode = varnode;
    }

    @Override
    public boolean isValid() {
      return true;
    }

    @Override
    public int size() {
      return varnode.getSize();
    }

    @Override
    public Varnode[] getVarnodes() {
      return new Varnode[] {varnode};
    }

    @Override
    public String getSerializationString() {
      return varnode.getAddress().toString(true) + ":" + varnode.getSize();
    }
  }

  private static Parameter stubParameter(
      String name,
      int ordinal,
      DataType dataType,
      SourceType source,
      boolean autoParameter,
      VariableStorage storage) {
    return stubParameter(name, ordinal, dataType, source, autoParameter, storage, null);
  }

  private static Parameter stubParameter(
      String name,
      int ordinal,
      DataType dataType,
      SourceType source,
      boolean autoParameter,
      VariableStorage storage,
      String comment) {
    return (Parameter)
        Proxy.newProxyInstance(
            Parameter.class.getClassLoader(),
            new Class<?>[] {Parameter.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getName" -> name;
                  case "getOrdinal" -> ordinal;
                  case "getDataType", "getFormalDataType" -> dataType;
                  case "getLength" -> dataType.getLength();
                  case "getSource" -> source;
                  case "isAutoParameter" -> autoParameter;
                  case "isValid" -> true;
                  case "getVariableStorage" -> storage;
                  case "getComment" -> comment;
                  case "equals" -> proxy == args[0];
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "toString" -> name + "@" + ordinal;
                  default -> throw new AssertionError("Unexpected Parameter." + method.getName());
                });
  }
}
