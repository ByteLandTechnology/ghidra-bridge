package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.util.Set;

final class FunctionRelationQueries {
  private final FunctionResolver resolver;

  FunctionRelationQueries(FunctionResolver resolver) {
    this.resolver = resolver;
  }

  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
    return getCallers(rawAddress, limit, cursor, null);
  }

  Page<FunctionCallResource> getCallers(
      String rawAddress, int limit, String cursor, Set<String> fields) {
    return getFunctionRelations(rawAddress, true, limit, cursor, fields);
  }

  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
    return getCallees(rawAddress, limit, cursor, null);
  }

  Page<FunctionCallResource> getCallees(
      String rawAddress, int limit, String cursor, Set<String> fields) {
    return getFunctionRelations(rawAddress, false, limit, cursor, fields);
  }

  private Page<FunctionCallResource> getFunctionRelations(
      String rawAddress, boolean callers, int limit, String cursor, Set<String> fields) {
    Function function = resolver.resolveFunction(rawAddress);
    Iterable<Function> related =
        callers
            ? function.getCallingFunctions(TaskMonitor.DUMMY)
            : function.getCalledFunctions(TaskMonitor.DUMMY);
    Page.Selector<Function> selector = Page.selector(limit, cursor);
    for (Function relatedFunction : related) {
      selector.offer(
          AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()), relatedFunction);
    }
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needNamespace = FieldProjections.allows(fields, "namespace");
    boolean needDemangled = FieldProjections.allows(fields, "demangled_name");
    FunctionCallResource.Direction direction =
        FieldProjections.allows(fields, "direction")
            ? (callers
                ? FunctionCallResource.Direction.CALLERS
                : FunctionCallResource.Direction.CALLEES)
            : null;
    return selector.finish(
        (relatedFunction, entry) -> {
          String name = needName || needDemangled ? relatedFunction.getName() : null;
          return new FunctionCallResource(
              entry,
              needName ? name : null,
              null,
              direction,
              needNamespace ? relatedFunction.getParentNamespace().getName(true) : null,
              needDemangled
                  ? CppSymbolNames.demangled(
                      relatedFunction.getProgram(), name, relatedFunction.getEntryPoint())
                  : null);
        });
  }
}
