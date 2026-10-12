package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.api.ApiFailures;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import org.junit.jupiter.api.Test;

class ScriptSymbolRenamerTest {
  private static final class InvalidNameScript extends GhidraScript {
    private InvalidNameScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}

  }

  @Test
  void invalidFunctionNameRemainsAClientError() {
    Symbol symbol = (Symbol) Proxy.newProxyInstance(
        Symbol.class.getClassLoader(), new Class<?>[] {Symbol.class},
        (proxy, method, arguments) -> switch (method.getName()) {
          case "getName" -> "original";
          case "getSymbolType" -> SymbolType.FUNCTION;
          case "getAddress", "getParentNamespace" -> null;
          default -> throw new AssertionError(method.getName());
        });
    SymbolTable table = (SymbolTable) Proxy.newProxyInstance(
        SymbolTable.class.getClassLoader(), new Class<?>[] {SymbolTable.class},
        (proxy, method, arguments) -> {
          if (method.getName().equals("createLabel")) {
            assertEquals("bad name", arguments[1]);
            throw new InvalidInputException("symbol names cannot contain whitespace");
          }
          throw new AssertionError(method.getName());
        });
    Program program = (Program) Proxy.newProxyInstance(
        Program.class.getClassLoader(), new Class<?>[] {Program.class},
        (proxy, method, arguments) -> {
          if (method.getName().equals("getSymbolTable")) {
            return table;
          }
          throw new AssertionError(method.getName());
        });
    GhidraSession session = new GhidraSession(new InvalidNameScript(program));
    var error = assertThrows(IllegalArgumentException.class,
        () -> ScriptSymbolRenamer.rename(session, symbol, "bad name"));
    var failure = ApiFailures.normalize(error);
    assertEquals(400, failure.status());
    assertEquals("invalid_request", failure.error().code());
  }
}
