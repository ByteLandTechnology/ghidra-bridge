package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
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
    List<RelatedEntry> entries = new ArrayList<>();
    Iterable<Function> related =
        callers
            ? function.getCallingFunctions(TaskMonitor.DUMMY)
            : function.getCalledFunctions(TaskMonitor.DUMMY);
    for (Function relatedFunction : related) {
      Address entryPoint = relatedFunction.getEntryPoint();
      entries.add(
          new RelatedEntry(AddressUtil.canonicalAddress(entryPoint), entryPoint, relatedFunction));
    }
    entries.sort(Comparator.comparing(RelatedEntry::entry));
    Page<RelatedEntry> page = Page.paginate(entries, limit, cursor, RelatedEntry::entry);
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needNamespace = FieldProjections.allows(fields, "namespace");
    boolean needDemangled = FieldProjections.allows(fields, "demangled_name");
    FunctionCallResource.Direction direction =
        FieldProjections.allows(fields, "direction")
            ? (callers
                ? FunctionCallResource.Direction.CALLERS
                : FunctionCallResource.Direction.CALLEES)
            : null;
    List<FunctionCallResource> items = new ArrayList<>(page.items().size());
    for (RelatedEntry item : page.items()) {
      Function relatedFunction = item.function();
      String name = needName || needDemangled ? relatedFunction.getName() : null;
      items.add(
          new FunctionCallResource(
              item.entry(),
              needName ? name : null,
              null,
              direction,
              needNamespace ? relatedFunction.getParentNamespace().getName(true) : null,
              needDemangled
                  ? CppSymbolNames.demangled(
                      relatedFunction.getProgram(), name, item.entryPoint())
                  : null));
    }
    return Page.of(items, page.limit(), page.nextCursor());
  }

  private record RelatedEntry(String entry, Address entryPoint, Function function) {}
}
