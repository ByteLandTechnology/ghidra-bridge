package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.NameCandidate;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.symbol.SymbolService.DemangleResult;
import ghidra.app.util.demangler.DemangledVariable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.List;

final class SymbolDemangling {
  private SymbolDemangling() {}

  static DemangleResult apply(GhidraSession context) {
    return context.withTransaction(() -> {
      var program = context.currentProgram();
      var monitor = context.flatApi().getMonitor();
      List<Symbol> candidates = new ArrayList<>();
      var symbols = program.getSymbolTable().getDefinedSymbols();
      while (symbols.hasNext()) {
        monitor.checkCancelled();
        Symbol symbol = symbols.next();
        if (symbol.isPrimary() && CppSymbolNames.isMangled(symbol.getName())) {
          candidates.add(symbol);
        }
      }
      int renamed = 0;
      int failed = 0;
      List<String> failures = new ArrayList<>();
      for (Symbol symbol : candidates) {
        monitor.checkCancelled();
        String name = symbol.getName();
        boolean applied = false;
        String error = "No supported C++ name";
        for (NameCandidate decoded :
            CppSymbolNames.decode(program, name, symbol.getAddress()).candidates()) {
          try {
            applied = new NameOnly(name, decoded).applyName(program, symbol.getAddress());
          } catch (InvalidInputException failure) {
            error = failure.getMessage();
          }
          if (applied) break;
        }
        if (applied) {
          renamed++;
        } else {
          failed++;
          if (failures.size() < 20) failures.add(name + ": " + error);
        }
      }
      return new DemangleResult(renamed, failed, failures);
    });
  }

  /**
   * Uses the native name operation without data, type, comment, or disassembly changes.
   *
   * <p>The subclass gives access to the protected applyDemangledName method. Ghidra then creates
   * the namespaces and keeps the mangled name as a secondary label.
   */
  private static final class NameOnly extends DemangledVariable {
    NameOnly(String mangled, NameCandidate decoded) {
      super(mangled, decoded.originalDemangled(), decoded.name());
      setNamespace(decoded.namespace());
    }

    boolean applyName(Program program, Address address) throws InvalidInputException {
      return applyDemangledName(address, true, true, program) != null;
    }
  }
}
