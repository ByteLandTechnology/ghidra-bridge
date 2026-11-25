package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.CppSymbolIndex;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.symbol.SymbolService.DemangleResult;
import ghidra.app.util.demangler.DemangledVariable;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;

final class SymbolDemangling {
  private SymbolDemangling() {}

  static DemangleResult apply(GhidraSession context) {
    Program precheckProgram = context.currentProgram();
    if (!context.holdsExecutionLock()
        && !context.cppSymbols().isSyncedWithProgram(precheckProgram)) {
      warmMissingOutsideLock(context, precheckProgram);
    }

    return context.withTransaction(
        () -> {
          var program = context.currentProgram();
          var monitor = context.script().getMonitor();
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
          CppSymbolIndex cppSymbols = context.cppSymbols();
          for (Symbol symbol : candidates) {
            monitor.checkCancelled();
            String name = symbol.getName();
            boolean applied = false;
            String error = "No supported C++ name";
            CppSymbolIndex.Entry entry = cppSymbols.lookup(program, name, symbol.getAddress());
            for (CppSymbolIndex.Candidate decoded : entry.candidates()) {
              try {
                applied = new NameOnly(decoded).applyName(program, symbol.getAddress());
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

  private static void warmMissingOutsideLock(GhidraSession context, Program program) {
    TaskMonitor monitor = context.script().getMonitor();
    List<WarmTarget> unindexed = new ArrayList<>();
    var symbols = program.getSymbolTable().getDefinedSymbols();
    while (symbols.hasNext()) {
      if (monitor != null && monitor.isCancelled()) {
        return;
      }
      Symbol symbol = symbols.next();
      if (symbol.isPrimary() && CppSymbolNames.isMangled(symbol.getName())) {
        unindexed.add(new WarmTarget(symbol.getName(), symbol.getAddress()));
      }
    }
    CppSymbolIndex cppSymbols = context.cppSymbols();
    for (WarmTarget target : unindexed) {
      if (monitor != null) {
        try {
          monitor.checkCancelled();
        } catch (CancelledException cancelled) {
          return;
        }
      }
      cppSymbols.warmOnDemand(program, target.name(), target.address());
    }
  }

  private record WarmTarget(String name, Address address) {}

  /**
   * Uses the native name operation without data, type, comment, or disassembly changes.
   *
   * <p>The subclass gives access to the protected applyDemangledName method. Ghidra then creates
   * the namespaces and keeps the mangled name as a secondary label.
   */
  private static final class NameOnly extends DemangledVariable {
    NameOnly(CppSymbolIndex.Candidate decoded) {
      super(decoded.mangled(), decoded.originalDemangled(), decoded.name());
      setNamespace(decoded.namespace());
    }

    boolean applyName(Program program, Address address) throws InvalidInputException {
      return applyDemangledName(address, true, true, program) != null;
    }
  }
}
