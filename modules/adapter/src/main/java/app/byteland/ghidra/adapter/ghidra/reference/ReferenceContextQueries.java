package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.reference.ReferenceContextResource;
import app.byteland.ghidra.service.reference.ReferenceContextResource.CallerSummary;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

final class ReferenceContextQueries {
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;

  private final GhidraSession context;

  ReferenceContextQueries(GhidraSession context) {
    this.context = context;
  }

  Page<ReferenceContextResource> listReferenceContext(
      String toRaw,
      String entryRaw,
      String symbolIdRaw,
      String type,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    int normalizedLimit = Page.clampLimit(limit);
    Address anchor = resolveTargetAddress(toRaw, entryRaw, symbolIdRaw);
    String canonicalAnchor = AddressUtil.canonicalAddress(anchor);
    long startedNanos = System.nanoTime();
    long timeoutNanos = Math.max(1L, scan.timeoutMs()) * NANOS_PER_MILLISECOND;

    Page.Selector<Reference> selector = Page.selector(normalizedLimit, cursor);
    Iterator<Reference> iterator = context.references(anchor, true).iterator();
    boolean timedOut = false;
    while (iterator.hasNext()) {
      Reference reference = iterator.next();
      if (ReferenceQuerySupport.matchesType(type, reference)) {
        String encoded =
            ReferenceDescriptions.referenceKey(reference, anchor, canonicalAnchor).encoded();
        selector.offer(encoded, reference);
      }
      if (elapsedNanos(startedNanos) >= timeoutNanos && iterator.hasNext()) {
        timedOut = true;
        break;
      }
    }

    if (timedOut) {
      ScanProgress timeoutProgress =
          new ScanProgress(
              ScanProgress.Kind.ADDRESS,
              canonicalAnchor,
              canonicalAnchor,
              null,
              null,
              false,
              ScanProgress.StopReason.TIMEOUT,
              elapsedNanos(startedNanos) / NANOS_PER_MILLISECOND);
      return Page.scanned(List.of(), normalizedLimit, null, timeoutProgress);
    }

    Program program = context.currentProgram();
    FunctionManager functionManager = program.getFunctionManager();
    Listing listing = program.getListing();
    Map<Address, CallerSummary> callerCache = new HashMap<>();

    Page<ReferenceContextResource> page =
        selector.finish(
            reference ->
                describeContext(
                    reference,
                    anchor,
                    canonicalAnchor,
                    program,
                    functionManager,
                    listing,
                    callerCache));

    List<ReferenceContextResource> items = page.items();
    String scannedStart = items.isEmpty() ? null : items.getFirst().from();
    String scannedEnd = items.isEmpty() ? null : items.getLast().from();
    ScanProgress.StopReason stopReason =
        page.nextCursor() != null
            ? ScanProgress.StopReason.LIMIT
            : ScanProgress.StopReason.COMPLETED;
    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            canonicalAnchor,
            canonicalAnchor,
            scannedStart,
            scannedEnd,
            stopReason == ScanProgress.StopReason.COMPLETED,
            stopReason,
            elapsedNanos(startedNanos) / NANOS_PER_MILLISECOND);
    return Page.scanned(items, normalizedLimit, page.nextCursor(), progress);
  }

  private Address resolveTargetAddress(String toRaw, String entryRaw, String symbolIdRaw) {
    String normalizedTo = trimOrNull(toRaw);
    String normalizedEntry = trimOrNull(entryRaw);
    String normalizedSymbolId = trimOrNull(symbolIdRaw);
    if (normalizedTo == null && normalizedEntry == null && normalizedSymbolId == null) {
      throw new IllegalArgumentException(
          "filter requires at least one of to, entry, or symbol_id");
    }

    Address resolved = null;
    if (normalizedSymbolId != null) {
      long symbolId = parseSymbolId(normalizedSymbolId);
      Symbol symbol = context.currentProgram().getSymbolTable().getSymbol(symbolId);
      if (symbol == null) {
        throw new NoSuchElementException("symbol not found: " + symbolId);
      }
      resolved = symbol.getAddress();
    }
    if (normalizedEntry != null) {
      Address entryAddress = context.parseAddress(normalizedEntry);
      Function function = context.currentProgram().getFunctionManager().getFunctionAt(entryAddress);
      if (function == null) {
        throw new NoSuchElementException("function not found: " + normalizedEntry);
      }
      Address functionEntry = function.getEntryPoint();
      if (resolved != null && !resolved.equals(functionEntry)) {
        throw new IllegalArgumentException("filter.entry conflicts with filter.symbol_id");
      }
      resolved = functionEntry;
    }
    if (normalizedTo != null) {
      Address toAddress = context.parseAddress(normalizedTo);
      if (resolved != null && !resolved.equals(toAddress)) {
        throw new IllegalArgumentException("filter.to conflicts with target symbol or entry");
      }
      resolved = toAddress;
    }
    return resolved;
  }

  private static ReferenceContextResource describeContext(
      Reference reference,
      Address anchor,
      String canonicalAnchor,
      Program program,
      FunctionManager functionManager,
      Listing listing,
      Map<Address, CallerSummary> callerCache) {
    ReferenceResource base = ReferenceDescriptions.describe(reference, anchor, canonicalAnchor);
    Address fromAddress = reference.getFromAddress();
    Function callerFunction =
        fromAddress == null ? null : functionManager.getFunctionContaining(fromAddress);
    CallerSummary caller = null;
    if (callerFunction != null) {
      caller =
          callerCache.computeIfAbsent(
              callerFunction.getEntryPoint(),
              entryPoint ->
                  new CallerSummary(
                      AddressUtil.canonicalAddress(entryPoint),
                      callerFunction.getName(),
                      String.valueOf(callerFunction.getParentNamespace()),
                      CppSymbolNames.demangled(program, callerFunction.getName(), entryPoint)));
    }
    boolean hasInstructionSite =
        caller != null || (fromAddress != null && listing.getInstructionContaining(fromAddress) != null);
    String callSite = hasInstructionSite ? base.from() : null;
    return new ReferenceContextResource(
        base.from(),
        base.to(),
        base.type(),
        base.operandIndex(),
        base.primary(),
        base.sourceType(),
        callSite,
        caller);
  }

  private static long parseSymbolId(String rawSymbolId) {
    try {
      return Long.parseLong(rawSymbolId);
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("filter.symbol_id must be a decimal id", error);
    }
  }

  private static String trimOrNull(String value) {
    if (value == null) return null;
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private static long elapsedNanos(long startedNanos) {
    return Math.max(0L, System.nanoTime() - startedNanos);
  }
}
