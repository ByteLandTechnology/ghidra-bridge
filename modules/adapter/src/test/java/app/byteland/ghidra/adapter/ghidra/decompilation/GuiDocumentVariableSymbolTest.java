package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import app.byteland.ghidra.service.decompilation.DecompilationResource.Token.Kind;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.Test;

class GuiDocumentVariableSymbolTest {

  @Test
  void populatesSymbolResourceForUncommittedAndCommittedVariableTokens() {
    GenericAddressSpace ram = new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0);
    Address entry = ram.getAddress(0x101000L);
    Address useAddr = ram.getAddress(0x10100cL);
    Function function = mockFunction("compute_temp", entry);

    HighSymbol tempLocal =
        new TokenHighSymbol(9001L, "uVar1", false, false, useAddr, null);
    ClangVariableToken tempToken = new StubVariableToken(tempLocal);
    SymbolResource localResource =
        GuiDocument.resolveSymbol(null, function, null, tempToken, Kind.VARIABLE);
    assertNotNull(localResource);
    assertEquals("9001", localResource.id());
    assertEquals("uVar1", localResource.name());
    assertEquals("ram:0010100c", localResource.address());
    assertEquals("compute_temp", localResource.namespace());
    assertEquals("Local Var", localResource.type());
    assertEquals("DEFAULT", localResource.sourceType());
    assertFalse(localResource.primary());

    HighSymbol inferredParam =
        new TokenHighSymbol(9002L, "param_1", true, false, null, null);
    ClangVariableToken paramToken = new StubVariableToken(inferredParam);
    SymbolResource paramResource =
        GuiDocument.resolveSymbol(null, function, null, paramToken, Kind.PARAMETER);
    assertNotNull(paramResource);
    assertEquals("9002", paramResource.id());
    assertEquals("param_1", paramResource.name());
    assertEquals("ram:00101000", paramResource.address());
    assertEquals("compute_temp", paramResource.namespace());
    assertEquals("Parameter", paramResource.type());

    Symbol backingSymbol =
        mockSymbol(42L, "saved_count", entry, "compute_temp", SymbolType.LOCAL_VAR);
    HighSymbol committedLocal =
        new TokenHighSymbol(9003L, "saved_count", false, false, useAddr, backingSymbol);
    ClangVariableToken committedToken = new StubVariableToken(committedLocal);
    SymbolResource committedResource =
        GuiDocument.resolveSymbol(null, function, null, committedToken, Kind.VARIABLE);
    assertNotNull(committedResource);
    assertEquals("42", committedResource.id());
    assertEquals("saved_count", committedResource.name());
    assertEquals("Local Var", committedResource.type());
    assertEquals("USER_DEFINED", committedResource.sourceType());

    ClangVariableToken constantToken = new StubVariableToken(tempLocal);
    assertNull(GuiDocument.resolveSymbol(null, function, null, constantToken, Kind.CONSTANT));
  }

  private static Function mockFunction(String name, Address entry) {
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> name;
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }

  private static Symbol mockSymbol(
      long id, String name, Address address, String namespaceName, SymbolType symbolType) {
    Namespace namespace =
        (Namespace)
            Proxy.newProxyInstance(
                Namespace.class.getClassLoader(),
                new Class<?>[] {Namespace.class},
                (proxy, method, args) ->
                    "getName".equals(method.getName()) ? namespaceName : null);
    return (Symbol)
        Proxy.newProxyInstance(
            Symbol.class.getClassLoader(),
            new Class<?>[] {Symbol.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getID" -> id;
                  case "getName" -> name;
                  case "getAddress" -> address;
                  case "getParentNamespace" -> namespace;
                  case "getSymbolType" -> symbolType;
                  case "getSource" -> SourceType.USER_DEFINED;
                  case "isPrimary" -> false;
                  case "getProgram" -> null;
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }

  private static final class StubVariableToken extends ClangVariableToken {
    private final HighSymbol symbol;

    StubVariableToken(HighSymbol symbol) {
      super(null);
      this.symbol = symbol;
    }

    @Override
    public HighSymbol getHighSymbol(HighFunction highFunction) {
      return symbol;
    }
  }

  private static final class TokenHighSymbol extends HighSymbol {
    private final long symbolId;
    private final String symbolName;
    private final boolean parameter;
    private final boolean global;
    private final Address pcAddress;
    private final Symbol backing;

    TokenHighSymbol(
        long symbolId,
        String symbolName,
        boolean parameter,
        boolean global,
        Address pcAddress,
        Symbol backing) {
      super(symbolId, symbolName, mockDataType(), false, false, null);
      this.symbolId = symbolId;
      this.symbolName = symbolName;
      this.parameter = parameter;
      this.global = global;
      this.pcAddress = pcAddress;
      this.backing = backing;
    }

    private static DataType mockDataType() {
      return (DataType)
          Proxy.newProxyInstance(
              DataType.class.getClassLoader(),
              new Class<?>[] {DataType.class},
              (proxy, method, args) -> "int");
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
    public boolean isParameter() {
      return parameter;
    }

    @Override
    public boolean isGlobal() {
      return global;
    }

    @Override
    public Address getPCAddress() {
      return pcAddress;
    }

    @Override
    public Symbol getSymbol() {
      return backing;
    }
  }
}
