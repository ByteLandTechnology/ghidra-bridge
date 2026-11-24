package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;

final class FunctionRelationQueries {
  private static final String FUNCTION_CALL_RESOURCE = "function_call";

  private final GhidraSession context;
  private final FunctionResolver resolver;

  FunctionRelationQueries(FunctionResolver resolver) {
    this(null, resolver);
  }

  FunctionRelationQueries(GhidraSession context, FunctionResolver resolver) {
    this.context = context;
    this.resolver = Objects.requireNonNull(resolver, "resolver");
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
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || context == null || !context.canCacheSnapshots()) {
      return selectRelationsBounded(function, callers, limit, cursor);
    }

    long modNumber = context.modificationNumber();
    String canonicalTarget = AddressUtil.canonicalAddress(function.getEntryPoint());
    String directionKey = callers ? "callers" : "callees";
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            FUNCTION_CALL_RESOURCE, modNumber, canonicalTarget, directionKey);
    String[] sortedKeys = context.querySnapshots().get(cacheKey);
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      for (Function relatedFunction : relatedFunctions(function, callers)) {
        keys.add(AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()));
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectRelationsBounded(function, callers, limit, cursor);
      }
      if (context.modificationNumber() == modNumber) {
        context.querySnapshots().put(cacheKey, sortedKeys);
      }
    }
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    return QuerySnapshotCache.slice(
        sortedKeys,
        limit,
        cursor,
        this::resolveOrNull,
        relatedFunction ->
            describeRelation(
                relatedFunction,
                AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()),
                direction));
  }

  private static Page<FunctionCallResource> selectRelationsBounded(
      Function function, boolean callers, int limit, String cursor) {
    Page.Selector<Function> selector = Page.selector(limit, cursor);
    for (Function relatedFunction : relatedFunctions(function, callers)) {
      String entry = AddressUtil.canonicalAddress(relatedFunction.getEntryPoint());
      if (selector.acceptsKey(entry)) {
        selector.offer(entry, relatedFunction);
      }
    }
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    return selector.finish(
        (relatedFunction, entry) -> describeRelation(relatedFunction, entry, direction));
  }

  private static Iterable<Function> relatedFunctions(Function function, boolean callers) {
    return callers
        ? function.getCallingFunctions(TaskMonitor.DUMMY)
        : function.getCalledFunctions(TaskMonitor.DUMMY);
  }

  private Function resolveOrNull(String canonicalEntry) {
    try {
      return resolver.resolveFunction(canonicalEntry);
    } catch (NoSuchElementException ignored) {
      return null;
    }
  }

  private static FunctionCallResource describeRelation(
      Function relatedFunction, String entry, FunctionCallResource.Direction direction) {
    String name = relatedFunction.getName();
    return new FunctionCallResource(
        entry,
        name,
        null,
        direction,
        relatedFunction.getParentNamespace().getName(true),
        CppSymbolNames.demangled(
            relatedFunction.getProgram(), name, relatedFunction.getEntryPoint()));
  }
}
