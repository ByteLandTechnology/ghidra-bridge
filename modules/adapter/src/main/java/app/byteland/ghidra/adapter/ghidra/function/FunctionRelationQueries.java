package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

final class FunctionRelationQueries {
  private final GhidraSession context;
  private final FunctionResolver resolver;

  FunctionRelationQueries(FunctionResolver resolver) {
    this(null, resolver);
  }

  FunctionRelationQueries(GhidraSession context, FunctionResolver resolver) {
    this.context = context;
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
    Iterable<Function> related =
        callers
            ? function.getCallingFunctions(TaskMonitor.DUMMY)
            : function.getCalledFunctions(TaskMonitor.DUMMY);
    Page.Selector<Function> selector = Page.selector(limit, cursor);
    for (Function relatedFunction : related) {
      selector.offer(
          AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()), relatedFunction);
    }
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    return selector.finish(
        (relatedFunction, entry) -> {
          String name = relatedFunction.getName();
          return new FunctionCallResource(
              entry,
              name,
              null,
              direction,
              relatedFunction.getParentNamespace().getName(true),
              CppSymbolNames.demangled(
                  context, relatedFunction.getProgram(), name, relatedFunction.getEntryPoint()));
        });
  }
}
