package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.lang.reflect.Proxy;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class HighFunctionVariableFallbackTest {

  @Test
  void skipsHighFunctionLookupForExternalThunkOrSummaryOnlyIncludes() {
    Function normal = mockFunction(false, false, new Parameter[0], new Variable[0]);
    Function external = mockFunction(true, false, new Parameter[0], new Variable[0]);
    Function thunk = mockFunction(false, true, new Parameter[0], new Variable[0]);

    assertTrue(FunctionServiceImpl.shouldReadHighFunction(normal, Set.of("locals")));
    assertTrue(FunctionServiceImpl.shouldReadHighFunction(normal, Set.of("parameters")));
    assertFalse(FunctionServiceImpl.shouldReadHighFunction(normal, Set.of()));
    assertFalse(FunctionServiceImpl.shouldReadHighFunction(normal, Set.of("calls")));
    assertFalse(FunctionServiceImpl.shouldReadHighFunction(external, Set.of("locals")));
    assertFalse(FunctionServiceImpl.shouldReadHighFunction(thunk, Set.of("parameters")));
  }

  @Test
  void mergesAndDeduplicatesLocalSymbolMapVariablesDeterministically() {
    DataType intType = mockNamedType("int");
    DataType uintType = mockNamedType("uint");
    Parameter committedParam = mockParameter(0, "committed_arg", intType, "EDI:4");
    Variable committedLocal = mockLocal("committed_local", intType, "Stack[-0x10]:4");
    Function function =
        mockFunction(
            false,
            false,
            new Parameter[] {committedParam},
            new Variable[] {committedLocal});

    HighSymbol dupParamByOrdinal =
        new StubHighSymbol(1L, "param_1", uintType, true, false, "EDI:4");
    HighSymbol inferredParam =
        new StubHighSymbol(2L, "param_2", uintType, true, false, "ESI:4");
    HighSymbol dupLocalByStorage =
        new StubHighSymbol(3L, "local_10", uintType, false, false, "Stack[-0x10]:4");
    HighSymbol dupLocalByName =
        new StubHighSymbol(4L, "committed_local", uintType, false, false, "HASH:1111:4");
    HighSymbol tempZ =
        new StubHighSymbol(5L, "uVar2", uintType, false, false, "HASH:2222:4");
    HighSymbol tempA =
        new StubHighSymbol(6L, "uVar1", intType, false, false, "HASH:3333:4");
    HighSymbol globalSym =
        new StubHighSymbol(7L, "DAT_00102000", intType, false, true, "0x00102000:4");

    StubHighFunction highFunction =
        new StubHighFunction(
            function,
            List.of(dupParamByOrdinal, inferredParam),
            List.of(
                dupParamByOrdinal,
                inferredParam,
                dupLocalByStorage,
                dupLocalByName,
                tempZ,
                tempA,
                globalSym));

    List<FunctionResource.ParameterResource> parameters =
        FunctionDescriptions.describeParameters(function, highFunction);
    assertEquals(2, parameters.size());
    assertEquals("committed_arg", parameters.get(0).name());
    assertEquals(0, parameters.get(0).ordinal());
    assertEquals("param_2", parameters.get(1).name());
    assertEquals(1, parameters.get(1).ordinal());
    assertEquals(DataTypeReference.named("/uint"), parameters.get(1).dataType());
    assertEquals(VariableStorageReference.serialization("ESI:4"), parameters.get(1).storage());

    List<FunctionResource.LocalVariableResource> locals =
        FunctionDescriptions.describeLocalVariables(function, highFunction);
    assertEquals(3, locals.size());
    assertEquals("committed_local", locals.get(0).name());
    assertEquals("uVar1", locals.get(1).name());
    assertEquals(DataTypeReference.named("/int"), locals.get(1).dataType());
    assertEquals("uVar2", locals.get(2).name());
    assertEquals(DataTypeReference.named("/uint"), locals.get(2).dataType());
  }

  @Test
  void mapsHighSymbolExceptionsToBadRequestAndMissingVariableToNotFound() {
    DataType intType = mockNamedType("int");
    DuplicateNameException duplicate = new DuplicateNameException("duplicate symbol uVar1");
    IllegalArgumentException dupMapped =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionVariableMutationSupport.runHighSymbolMutation(
                    () -> {
                      throw duplicate;
                    }));
    assertSame(duplicate, dupMapped.getCause());
    ApiFailures.Failure dupApi = ApiFailures.normalize(dupMapped);
    assertEquals(400, dupApi.status());
    assertEquals("invalid_request", dupApi.error().code());

    InvalidInputException invalid = new InvalidInputException("invalid variable name");
    IllegalArgumentException invalidMapped =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                FunctionVariableMutationSupport.runHighSymbolMutation(
                    () -> {
                      throw invalid;
                    }));
    assertSame(invalid, invalidMapped.getCause());
    ApiFailures.Failure invalidApi = ApiFailures.normalize(invalidMapped);
    assertEquals(400, invalidApi.status());
    assertEquals("invalid_request", invalidApi.error().code());

    AtomicInteger readerCalls = new AtomicInteger();
    Function normal = mockFunction(false, false, new Parameter[0], new Variable[0]);
    StubHighFunction emptyHigh = new StubHighFunction(normal, List.of(), List.of());
    NoSuchElementException missing =
        assertThrows(
            NoSuchElementException.class,
            () ->
                FunctionLocalVariableMutations.patchLocalVariable(
                    null,
                    normal,
                    "uVar99",
                    "renamed",
                    null,
                    ref -> intType,
                    fn -> {
                      readerCalls.incrementAndGet();
                      return emptyHigh;
                    }));
    assertEquals(1, readerCalls.get());
    ApiFailures.Failure missingApi = ApiFailures.normalize(missing);
    assertEquals(404, missingApi.status());
    assertEquals("resource_not_found", missingApi.error().code());

    Function external = mockFunction(true, false, new Parameter[0], new Variable[0]);
    assertThrows(
        NoSuchElementException.class,
        () ->
            FunctionLocalVariableMutations.patchLocalVariable(
                null,
                external,
                "uVar1",
                "renamed",
                null,
                ref -> intType,
                fn -> {
                  readerCalls.incrementAndGet();
                  return emptyHigh;
                }));
    assertEquals(1, readerCalls.get());
  }

  private static DataType mockNamedType(String name) {
    return (DataType)
        Proxy.newProxyInstance(
            DataType.class.getClassLoader(),
            new Class<?>[] {DataType.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getName", "getDisplayName", "toString" -> name;
                  case "getPathName" -> "/" + name;
                  default -> null;
                });
  }

  private static Function mockFunction(
      boolean external, boolean thunk, Parameter[] parameters, Variable[] locals) {
    GenericAddressSpace ram = new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0);
    GenericAddressSpace stack =
        new GenericAddressSpace("Stack", 64, GenericAddressSpace.TYPE_STACK, 1);
    Address entry = ram.getAddress(0x101000L);
    AddressFactory factory =
        (AddressFactory)
            Proxy.newProxyInstance(
                AddressFactory.class.getClassLoader(),
                new Class<?>[] {AddressFactory.class},
                (proxy, method, args) ->
                    "getStackSpace".equals(method.getName()) ? stack : null);
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    "getAddressFactory".equals(method.getName()) ? factory : null);
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "isExternal" -> external;
                  case "isThunk" -> thunk;
                  case "getParameters" -> parameters;
                  case "getParameterCount" -> parameters.length;
                  case "getLocalVariables" -> locals;
                  case "getProgram" -> program;
                  case "getEntryPoint" -> entry;
                  case "hasVarArgs", "hasNoReturn", "isInline", "hasCustomVariableStorage" ->
                      false;
                  case "getCallingConventionName" -> "__stdcall";
                  default -> {
                    if (method.getReturnType() == boolean.class) {
                      yield false;
                    }
                    if (method.getReturnType() == int.class) {
                      yield 0;
                    }
                    if (method.getReturnType() == long.class) {
                      yield 0L;
                    }
                    yield null;
                  }
                });
  }

  private static Parameter mockParameter(
      int ordinal, String name, DataType dataType, String serialization) {
    VariableStorage storage = new StubStorage(serialization);
    return (Parameter)
        Proxy.newProxyInstance(
            Parameter.class.getClassLoader(),
            new Class<?>[] {Parameter.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getOrdinal" -> ordinal;
                  case "getName" -> name;
                  case "getFormalDataType", "getDataType" -> dataType;
                  case "getVariableStorage" -> storage;
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }

  private static Variable mockLocal(String name, DataType dataType, String serialization) {
    VariableStorage storage = new StubStorage(serialization);
    return (Variable)
        Proxy.newProxyInstance(
            Variable.class.getClassLoader(),
            new Class<?>[] {Variable.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getName" -> name;
                  case "getDataType" -> dataType;
                  case "getVariableStorage" -> storage;
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }

  private static final class StubStorage extends VariableStorage {
    private final String serialization;

    StubStorage(String serialization) {
      this.serialization = serialization;
    }

    @Override
    public String getSerializationString() {
      return serialization;
    }

    @Override
    public boolean isBadStorage() {
      return false;
    }

    @Override
    public boolean isUnassignedStorage() {
      return false;
    }
  }

  private static final class StubHighFunction extends HighFunction {
    private final LocalSymbolMap symbolMap;

    StubHighFunction(
        Function backingFunction, List<HighSymbol> params, List<HighSymbol> symbols) {
      super(backingFunction, null, null, null);
      this.symbolMap = new StubLocalSymbolMap(this, params, symbols);
    }

    @Override
    public LocalSymbolMap getLocalSymbolMap() {
      return symbolMap;
    }
  }

  private static final class StubLocalSymbolMap extends LocalSymbolMap {
    private final List<HighSymbol> params;
    private final List<HighSymbol> symbols;

    StubLocalSymbolMap(
        HighFunction highFunction, List<HighSymbol> params, List<HighSymbol> symbols) {
      super(highFunction, null);
      this.params = params;
      this.symbols = symbols;
    }

    @Override
    public int getNumParams() {
      return params.size();
    }

    @Override
    public HighSymbol getParamSymbol(int index) {
      return params.get(index);
    }

    @Override
    public Iterator<HighSymbol> getSymbols() {
      return symbols.iterator();
    }
  }

  private static final class StubHighSymbol extends HighSymbol {
    private final long symbolId;
    private final String symbolName;
    private final DataType dataType;
    private final boolean parameter;
    private final boolean global;
    private final VariableStorage storage;

    StubHighSymbol(
        long symbolId,
        String symbolName,
        DataType dataType,
        boolean parameter,
        boolean global,
        String serialization) {
      super(symbolId, symbolName, dataType, false, false, null);
      this.symbolId = symbolId;
      this.symbolName = symbolName;
      this.dataType = dataType;
      this.parameter = parameter;
      this.global = global;
      this.storage = new StubStorage(serialization);
    }

    @Override
    public long getId() {
      return symbolId;
    }

    @Override
    public String getName() {
      return symbolName;
    }

    @Override
    public DataType getDataType() {
      return dataType;
    }

    @Override
    public boolean isParameter() {
      return parameter;
    }

    @Override
    public boolean isGlobal() {
      return global;
    }

    @Override
    public VariableStorage getStorage() {
      return storage;
    }
  }
}
