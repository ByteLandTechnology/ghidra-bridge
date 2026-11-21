package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class FunctionRelationQueries {
  private final FunctionResolver resolver;

  FunctionRelationQueries(FunctionResolver resolver) {
    this.resolver = resolver;
  }

  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
    return getFunctionRelations(rawAddress, true, limit, cursor);
  }

  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
    return getFunctionRelations(rawAddress, false, limit, cursor);
  }

  private Page<FunctionCallResource> getFunctionRelations(
      String rawAddress, boolean callers, int limit, String cursor) {
    Function function = resolver.resolveFunction(rawAddress);
    Map<String, FunctionCallResource> rowsByKey = new LinkedHashMap<>();
    Set<Address> coveredEntries = new HashSet<>();
    if (callers) {
      collectCallerReferences(function, rowsByKey, coveredEntries);
    } else {
      collectCalleeReferences(function, rowsByKey, coveredEntries);
    }
    Iterable<Function> related =
        callers
            ? function.getCallingFunctions(TaskMonitor.DUMMY)
            : function.getCalledFunctions(TaskMonitor.DUMMY);
    for (Function relatedFunction : related) {
      if (!coveredEntries.contains(relatedFunction.getEntryPoint())) {
        addRow(
            rowsByKey,
            relatedFunction,
            null,
            callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES);
      }
    }
    List<FunctionCallResource> rows = new ArrayList<>(rowsByKey.values());
    rows.sort(
        Comparator.comparing(FunctionCallResource::entry)
            .thenComparing(row -> row.callSite() == null ? "" : row.callSite()));
    return Page.paginate(rows, limit, cursor, FunctionRelationQueries::cursorKey);
  }

  private static void collectCallerReferences(
      Function target, Map<String, FunctionCallResource> rowsByKey, Set<Address> coveredEntries) {
    Program program = target.getProgram();
    FunctionManager functionManager = program.getFunctionManager();
    ReferenceIterator references =
        program.getReferenceManager().getReferencesTo(target.getEntryPoint());
    while (references.hasNext()) {
      Reference ref = references.next();
      Function caller = functionManager.getFunctionContaining(ref.getFromAddress());
      if (caller == null) {
        continue;
      }
      boolean validRelation =
          ref.getReferenceType().isCall()
              || (ref.getReferenceType().isJump() && !caller.equals(target));
      if (!validRelation) {
        continue;
      }
      coveredEntries.add(caller.getEntryPoint());
      addRow(
          rowsByKey,
          caller,
          AddressUtil.canonicalAddress(ref.getFromAddress()),
          FunctionCallResource.Direction.CALLERS);
    }
  }

  private static void collectCalleeReferences(
      Function source, Map<String, FunctionCallResource> rowsByKey, Set<Address> coveredEntries) {
    Program program = source.getProgram();
    ReferenceManager referenceManager = program.getReferenceManager();
    AddressIterator sourceAddresses =
        referenceManager.getReferenceSourceIterator(source.getBody(), true);
    while (sourceAddresses.hasNext()) {
      Address fromAddress = sourceAddresses.next();
      for (Reference ref : referenceManager.getReferencesFrom(fromAddress)) {
        Function callee = resolveTargetFunction(program, ref.getToAddress());
        if (callee == null) {
          continue;
        }
        boolean validRelation =
            ref.getReferenceType().isCall()
                || (ref.getReferenceType().isJump()
                    && !callee.equals(source)
                    && !source.getBody().contains(ref.getToAddress()));
        if (!validRelation) {
          continue;
        }
        coveredEntries.add(callee.getEntryPoint());
        addRow(
            rowsByKey,
            callee,
            AddressUtil.canonicalAddress(fromAddress),
            FunctionCallResource.Direction.CALLEES);
      }
    }
  }

  private static Function resolveTargetFunction(Program program, Address toAddress) {
    Function direct = program.getFunctionManager().getFunctionAt(toAddress);
    if (direct != null) {
      return direct;
    }
    if (toAddress != null && toAddress.isExternalAddress()) {
      Symbol primary = program.getSymbolTable().getPrimarySymbol(toAddress);
      if (primary != null && primary.getObject() instanceof Function externalFn) {
        return externalFn;
      }
    }
    return null;
  }

  private static void addRow(
      Map<String, FunctionCallResource> rowsByKey,
      Function relatedFunction,
      String callSite,
      FunctionCallResource.Direction direction) {
    FunctionCallResource row =
        new FunctionCallResource(
            AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()),
            relatedFunction.getName(),
            callSite,
            direction,
            relatedFunction.getParentNamespace().getName(true),
            CppSymbolNames.demangled(
                relatedFunction.getProgram(),
                relatedFunction.getName(),
                relatedFunction.getEntryPoint()));
    rowsByKey.putIfAbsent(cursorKey(row), row);
  }

  private static String cursorKey(FunctionCallResource row) {
    return CompositeCursor.key(row.entry(), row.callSite() == null ? "" : row.callSite());
  }
}
