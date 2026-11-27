package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;

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
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || context == null || !context.canCacheSnapshots()) {
      return selectRelationsBounded(function, callers, limit, cursor, fields);
    }

    Program snapshotProgram = context.currentProgramOrNull();
    QuerySnapshotCache snapshots = context.querySnapshots();
    long clearEpoch = snapshots.clearEpoch();
    long modNumber = context.modificationNumber();
    String canonicalTarget = AddressUtil.canonicalAddress(function.getEntryPoint());
    String directionKey = callers ? "callers" : "callees";
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            FUNCTION_CALL_RESOURCE, modNumber, canonicalTarget, directionKey);
    String[] sortedKeys = snapshots.get(cacheKey);
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      for (Function relatedFunction : relatedFunctions(function, callers)) {
        keys.add(AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()));
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectRelationsBounded(function, callers, limit, cursor, fields);
      }
      if (context.currentProgramOrNull() == snapshotProgram
          && context.modificationNumber() == modNumber) {
        snapshots.putIfUnchanged(clearEpoch, cacheKey, sortedKeys);
      }
    }
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needNamespace = FieldProjections.allows(fields, "namespace");
    boolean needDemangled = FieldProjections.allows(fields, "demangled_name");
    FunctionCallResource.Direction direction = projectedDirection(callers, fields);
    return QuerySnapshotCache.slice(
        sortedKeys,
        limit,
        cursor,
        this::resolveOrNull,
        (relatedFunction, entry) ->
            describeRelation(
                relatedFunction, entry, direction, needName, needNamespace, needDemangled));
  }

  private static Page<FunctionCallResource> selectRelationsBounded(
      Function function, boolean callers, int limit, String cursor, Set<String> fields) {
    Page.Selector<Function> selector = Page.selector(limit, cursor);
    for (Function relatedFunction : relatedFunctions(function, callers)) {
      selector.offer(
          AddressUtil.canonicalAddress(relatedFunction.getEntryPoint()), relatedFunction);
    }
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needNamespace = FieldProjections.allows(fields, "namespace");
    boolean needDemangled = FieldProjections.allows(fields, "demangled_name");
    FunctionCallResource.Direction direction = projectedDirection(callers, fields);
    return selector.finish(
        (relatedFunction, entry) ->
            describeRelation(
                relatedFunction, entry, direction, needName, needNamespace, needDemangled));
  }

  private static FunctionCallResource.Direction projectedDirection(
      boolean callers, Set<String> fields) {
    if (!FieldProjections.allows(fields, "direction")) {
      return null;
    }
    return callers
        ? FunctionCallResource.Direction.CALLERS
        : FunctionCallResource.Direction.CALLEES;
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
      Function relatedFunction,
      String entry,
      FunctionCallResource.Direction direction,
      boolean needName,
      boolean needNamespace,
      boolean needDemangled) {
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
  }
}
