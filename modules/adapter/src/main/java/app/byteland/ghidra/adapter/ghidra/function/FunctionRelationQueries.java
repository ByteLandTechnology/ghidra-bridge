package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

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
    List<FunctionCallResource> rows = new ArrayList<>();
    Iterable<Function> related =
        callers
            ? function.getCallingFunctions(TaskMonitor.DUMMY)
            : function.getCalledFunctions(TaskMonitor.DUMMY);
    for (Function relatedFunction : related) {
      rows.add(
          new FunctionCallResource(
              AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()),
              relatedFunction.getName(),
              null,
              callers
                  ? FunctionCallResource.Direction.CALLERS
                  : FunctionCallResource.Direction.CALLEES));
    }
    rows.sort(Comparator.comparing(FunctionCallResource::entry));
    return Page.paginate(rows, limit, cursor, FunctionCallResource::entry);
  }
}
